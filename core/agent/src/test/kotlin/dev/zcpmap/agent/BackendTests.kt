package dev.zcpmap.agent

import com.sun.net.httpserver.HttpServer
import dev.zcpmap.protocol.StrictJsonParser
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

private fun parse(s: String): JsonObject = StrictJsonParser.parseObject(s)

class TextToolProtocolTest {
    @Test
    fun parsesTaggedCallsAndStripsReasoning() {
        val raw = "<think>peer looks fine</think>Scanning now.\n<tool_call>{\"name\": \"scan_and_verify_uwb_peers\", \"arguments\": {\"max_results\": 4}}</tool_call>"
        val p = TextToolProtocol.parse(raw, "x")
        assertEquals("Scanning now.", p.visibleText)
        assertEquals("peer looks fine", p.reasoning)
        assertEquals(1, p.calls.size)
        assertEquals("scan_and_verify_uwb_peers", p.calls[0].name)
        assertEquals("4", p.calls[0].arguments.jsonObject["max_results"]!!.jsonPrimitive.content)
        assertEquals("x0", p.calls[0].id)
    }

    @Test
    fun toleratesSmallModelQuirks() {
        val unterminated = TextToolProtocol.parse("<tool_call>{\"name\":\"scan_and_verify_uwb_peers\",\"parameters\":{}}", "a")
        assertEquals("scan_and_verify_uwb_peers", unterminated.calls.single().name)
        val fenced = TextToolProtocol.parse("```json\n{\"name\":\"terminate_and_wipe_session\",\"arguments\":{\"peer_id\":\"peer-0011223344556677\",\"reason\":\"policy\"}}\n```", "b")
        assertEquals("terminate_and_wipe_session", fenced.calls.single().name)
        val bare = TextToolProtocol.parse("{\"name\":\"scan_and_verify_uwb_peers\",\"arguments\":\"{\\\"max_results\\\":2}\"}", "c")
        assertEquals("2", bare.calls.single().arguments.jsonObject["max_results"]!!.jsonPrimitive.content)
        val plain = TextToolProtocol.parse("All done, nothing to do.", "d")
        assertTrue(plain.calls.isEmpty())
        assertEquals("All done, nothing to do.", plain.visibleText)
    }

    @Test
    fun invalidJsonBecomesARejectableCall() {
        val p = TextToolProtocol.parse("<tool_call>{\"name\":\"propose_agent_contract\", \"arguments\": {bad json}}</tool_call>", "e")
        val call = p.calls.single()
        assertEquals("propose_agent_contract", call.name)
        assertIs<JsonPrimitive>(call.arguments) // the airlock rejects non-object arguments
        val dup = TextToolProtocol.parse("<tool_call>{\"name\":\"a\",\"name\":\"b\",\"arguments\":{}}</tool_call>", "f")
        assertIs<JsonPrimitive>(dup.calls.single().arguments)
    }

    @Test
    fun capsCallsPerReply() {
        val raw = (1..10).joinToString("\n") { "<tool_call>{\"name\":\"scan_and_verify_uwb_peers\",\"arguments\":{}}</tool_call>" }
        assertEquals(TextToolProtocol.MAX_CALLS_PER_REPLY, TextToolProtocol.parse(raw, "g").calls.size)
    }
}

class LocalNetworkPolicyTest {
    private fun fakeResolve(ip: String): (String) -> Array<InetAddress> = { arrayOf(InetAddress.getByName(ip)) }

    @Test
    fun plainHttpOnlyToOwnNetwork() {
        listOf("127.0.0.1", "192.168.1.20", "10.0.0.5", "172.20.1.1", "100.101.102.103", "169.254.10.10", "fd12:3456::1", "::1").forEach { ip ->
            assertIs<LocalNetworkPolicy.Verdict.Allowed>(LocalNetworkPolicy.checkResolved("http://server:11434", fakeResolve(ip)), ip)
        }
        listOf("8.8.8.8", "104.18.1.1", "2606:4700::1111").forEach { ip ->
            assertIs<LocalNetworkPolicy.Verdict.Refused>(LocalNetworkPolicy.checkResolved("http://server:11434", fakeResolve(ip)), ip)
        }
        assertIs<LocalNetworkPolicy.Verdict.Allowed>(LocalNetworkPolicy.checkResolved("https://ai.example.net", fakeResolve("8.8.8.8")))
        assertIs<LocalNetworkPolicy.Verdict.Refused>(LocalNetworkPolicy.checkUrlShape("ftp://x"))
        assertIs<LocalNetworkPolicy.Verdict.Refused>(LocalNetworkPolicy.checkUrlShape("http://user:pw@192.168.1.2"))
    }

    @Test
    fun endpointNormalisation() {
        assertEquals("http://h:11434/v1/chat/completions", OpenAiCompatibleBackend.chatCompletionsUrl("http://h:11434"))
        assertEquals("http://h:1234/v1/chat/completions", OpenAiCompatibleBackend.chatCompletionsUrl("http://h:1234/v1/"))
        assertEquals("https://h/v1/chat/completions", OpenAiCompatibleBackend.chatCompletionsUrl("https://h/v1/chat/completions"))
    }
}

/** Records requests and replies from a script. */
class ScriptedHttp(private val replies: List<(JsonObject) -> HttpReply>) : HttpTransport {
    val requests = CopyOnWriteArrayList<JsonObject>()
    val urls = CopyOnWriteArrayList<String>()
    val headers = CopyOnWriteArrayList<Map<String, String>>()
    override suspend fun postJson(url: String, headers: Map<String, String>, body: String): HttpReply {
        val req = StrictJsonParser.parseObject(body, StrictJsonParser.Limits(maxBytes = 4 shl 20, maxDepth = 64, maxStringChars = 1 shl 20))
        requests += req; urls += url; this.headers += headers
        val i = requests.size - 1
        return if (i < replies.size) replies[i](req) else HttpReply(500, "{\"error\":\"script exhausted\"}", null)
    }

    companion object {
        fun chat(content: String?, toolCalls: String? = null, finish: String = "stop") = HttpReply(200,
            "{\"id\":\"x\",\"object\":\"chat.completion\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":" +
                (content?.let { JsonPrimitive(it).toString() } ?: "null") +
                (toolCalls?.let { ",\"tool_calls\":$it" } ?: "") +
                "},\"finish_reason\":\"$finish\"}],\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":30,\"total_tokens\":150}}", null)
    }
}

class OpenAiCompatibleBackendTest {
    private val cfg = LocalServerConfig("http://192.168.1.20:11434", "qwen2.5:7b-instruct", token = "my-token")
    private val history = listOf(
        ChatItem.User("<operator_directive>scan</operator_directive>"),
        ChatItem.Assistant("", "", listOf(ToolCallRequest("call_1", ToolCatalog.SCAN, buildJsonObject { put("max_results", 4) }))),
        ChatItem.ToolResult("call_1", ToolCatalog.SCAN, "{\"peers\":[]}", false),
    )

    @Test
    fun nativeRequestShapeMatchesOpenAiFormat() = runBlocking {
        val http = ScriptedHttp(listOf({ _ -> ScriptedHttp.chat("No peers.") }))
        val b = OpenAiCompatibleBackend(cfg, http)
        val out = b.complete("SYS", history, ToolCatalog.all)
        assertIs<BackendOutcome.Success>(out)
        assertEquals("No peers.", out.turn.text)
        assertEquals(120L, out.turn.inputTokens)
        assertEquals("http://192.168.1.20:11434/v1/chat/completions", http.urls[0])
        assertEquals("Bearer my-token", http.headers[0]["authorization"])
        val req = http.requests[0]
        assertEquals("qwen2.5:7b-instruct", req["model"]!!.jsonPrimitive.content)
        assertEquals("false", req["stream"]!!.jsonPrimitive.content)
        assertNull(req["tool_choice"], "Ollama ignores tool_choice; never send it")
        val tools = req["tools"]!!.jsonArray
        assertEquals(7, tools.size)
        assertEquals("function", tools[0].jsonObject["type"]!!.jsonPrimitive.content)
        assertEquals("false", tools[0].jsonObject["function"]!!.jsonObject["parameters"]!!.jsonObject["additionalProperties"]!!.jsonPrimitive.content)
        val msgs = req["messages"]!!.jsonArray
        assertEquals(listOf("system", "user", "assistant", "tool"), msgs.map { it.jsonObject["role"]!!.jsonPrimitive.content })
        val tc = msgs[2].jsonObject["tool_calls"]!!.jsonArray[0].jsonObject
        assertEquals("call_1", tc["id"]!!.jsonPrimitive.content)
        assertEquals("{\"max_results\":4}", tc["function"]!!.jsonObject["arguments"]!!.jsonPrimitive.content) // arguments as a JSON string
        assertEquals("call_1", msgs[3].jsonObject["tool_call_id"]!!.jsonPrimitive.content)
    }

    @Test
    fun parsesOllamaStyleToolCallsWithStringArguments() = runBlocking {
        val calls = "[{\"id\":\"call_abc\",\"index\":0,\"type\":\"function\",\"function\":{\"name\":\"initiate_secure_handshake\",\"arguments\":\"{\\\"peer_id\\\":\\\"peer-0011223344556677\\\"}\"}}]"
        val http = ScriptedHttp(listOf({ _ -> ScriptedHttp.chat("", calls, "tool_calls") }))
        val out = OpenAiCompatibleBackend(cfg, http).complete("SYS", history, ToolCatalog.all)
        assertIs<BackendOutcome.Success>(out)
        val c = out.turn.toolCalls.single()
        assertEquals("call_abc", c.id)
        assertEquals("peer-0011223344556677", c.arguments.jsonObject["peer_id"]!!.jsonPrimitive.content)
        assertEquals(StopKind.TOOL_CALLS, out.turn.stop)
    }

    @Test
    fun fallsBackToTextProtocolWhenModelHasNoToolSupport() = runBlocking {
        val http = ScriptedHttp(listOf(
            { _ -> HttpReply(400, "{\"error\":{\"message\":\"registry.ollama.ai/library/gemma2:2b does not support tools\"}}", null) },
            { _ -> ScriptedHttp.chat("<tool_call>{\"name\":\"scan_and_verify_uwb_peers\",\"arguments\":{}}</tool_call>") },
        ))
        val b = OpenAiCompatibleBackend(cfg, http)
        val out = b.complete("SYS", history, ToolCatalog.all)
        assertIs<BackendOutcome.Success>(out)
        assertEquals(ToolCatalog.SCAN, out.turn.toolCalls.single().name)
        assertEquals(false, b.usingNativeTools)
        val second = http.requests[1]
        assertNull(second["tools"])
        val msgs = second["messages"]!!.jsonArray
        assertTrue(msgs[0].jsonObject["content"]!!.jsonPrimitive.content.contains("<tool_call>"), "text protocol instructions in system prompt")
        assertEquals(listOf("system", "user", "assistant", "user"), msgs.map { it.jsonObject["role"]!!.jsonPrimitive.content })
        assertTrue(msgs[3].jsonObject["content"]!!.jsonPrimitive.content.startsWith("<tool_result id=\"call_1\""))
    }

    @Test
    fun errorMapping() = runBlocking {
        fun outcome(r: HttpReply) = runBlocking { OpenAiCompatibleBackend(cfg, ScriptedHttp(listOf({ _ -> r }))).complete("S", history, ToolCatalog.all) }
        assertIs<BackendOutcome.Fatal>(outcome(HttpReply(404, "{\"error\":\"model 'x' not found\"}", null)))
        assertIs<BackendOutcome.Fatal>(outcome(HttpReply(401, "unauthorized", null)))
        assertIs<BackendOutcome.Retryable>(outcome(HttpReply(503, "loading model", 2)))
        assertIs<BackendOutcome.TranscriptRejected>(outcome(HttpReply(400, "{\"error\":{\"message\":\"context length exceeded\"}}", null)))
        val down = OpenAiCompatibleBackend(cfg, HttpTransport { _, _, _ -> throw java.net.ConnectException("refused") })
        assertIs<BackendOutcome.Retryable>(down.complete("S", history, ToolCatalog.all))
        val publicHttp = OpenAiCompatibleBackend(cfg.copy(baseUrl = "http://8.8.8.8:11434"), UrlConnectionTransport())
        assertIs<BackendOutcome.Fatal>(publicHttp.complete("S", history, ToolCatalog.all))
    }

    /** Real sockets: a local HTTP server speaking the OpenAI format, reached through UrlConnectionTransport. */
    @Test
    fun realHttpRoundTripOverLoopback() = runBlocking {
        val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        val seen = CopyOnWriteArrayList<String>()
        server.createContext("/v1/chat/completions") { ex ->
            seen += ex.requestBody.readBytes().toString(Charsets.UTF_8)
            val body = ScriptedHttp.chat("pong").body.toByteArray()
            ex.responseHeaders.add("content-type", "application/json")
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        server.start()
        try {
            val b = OpenAiCompatibleBackend(cfg.copy(baseUrl = "http://127.0.0.1:${server.address.port}"))
            val out = b.complete("SYS", listOf(ChatItem.User("ping")), ToolCatalog.all)
            assertIs<BackendOutcome.Success>(out)
            assertEquals("pong", out.turn.text)
            assertTrue(seen.single().contains("\"qwen2.5:7b-instruct\""))
        } finally {
            server.stop(0)
        }
    }
}

/** Fake LiteRT-LM style engine: stateful conversation, records everything it is asked to do. */
class FakeEngine(private val replies: ArrayDeque<EngineReply>) : LocalLlmEngine {
    override val modelName = "fake-1b"
    val starts = CopyOnWriteArrayList<Triple<String, List<EngineMessage>, List<ToolSpec>?>>()
    val sent = CopyOnWriteArrayList<EngineMessage>()
    var failNext: Exception? = null
    override suspend fun startConversation(systemPrompt: String, history: List<EngineMessage>, tools: List<ToolSpec>?) {
        starts += Triple(systemPrompt, history, tools)
    }
    override suspend fun send(message: EngineMessage): EngineReply {
        failNext?.let { failNext = null; throw it }
        sent += message
        return replies.removeFirstOrNull() ?: EngineReply("done", emptyList())
    }
    override fun close() {}
}

class OnDeviceBackendTest {
    @Test
    fun textProtocolSendsOnlyNewMessagesAndRestartsAfterReset() = runBlocking {
        val engine = FakeEngine(ArrayDeque(listOf(
            EngineReply("<tool_call>{\"name\":\"scan_and_verify_uwb_peers\",\"arguments\":{}}</tool_call>", emptyList()),
            EngineReply("No peers nearby.", emptyList()),
            EngineReply("ok", emptyList()),
        )))
        val b = OnDeviceBackend(engine, nativeTools = false)
        val h = ArrayList<ChatItem>()
        h += ChatItem.User("hello")
        val t1 = (b.complete("SYS", h, ToolCatalog.all) as BackendOutcome.Success).turn
        assertEquals(1, engine.starts.size)
        assertTrue(engine.starts[0].first.contains("<tool_call>"), "text protocol instructions appended")
        assertNull(engine.starts[0].third)
        h += ChatItem.Assistant(t1.text, t1.raw, t1.toolCalls)
        h += ChatItem.ToolResult(t1.toolCalls[0].id, ToolCatalog.SCAN, "{\"peers\":[]}", false)
        val t2 = (b.complete("SYS", h, ToolCatalog.all) as BackendOutcome.Success).turn
        assertEquals("No peers nearby.", t2.text)
        assertEquals(1, engine.starts.size, "second call must reuse the engine conversation")
        val second = engine.sent[1] as EngineMessage.User
        assertTrue(second.text.startsWith("<tool_result"))
        b.reset()
        b.complete("SYS", listOf(ChatItem.User("again")), ToolCatalog.all)
        assertEquals(2, engine.starts.size, "reset must start a fresh conversation")
    }

    @Test
    fun nativeToolsUseToolResponsesAndReplayHistory() = runBlocking {
        val args = buildJsonObject { put("peer_id", "peer-0011223344556677") }
        val engine = FakeEngine(ArrayDeque(listOf(
            EngineReply("", listOf(EngineToolCall(ToolCatalog.HANDSHAKE, args))),
            EngineReply("Connected.", emptyList()),
        )))
        val b = OnDeviceBackend(engine, nativeTools = true)
        val h = arrayListOf<ChatItem>(ChatItem.User("connect"))
        val t1 = (b.complete("SYS", h, ToolCatalog.all) as BackendOutcome.Success).turn
        assertEquals(ToolCatalog.HANDSHAKE, t1.toolCalls.single().name)
        assertEquals(7, engine.starts[0].third!!.size)
        h += ChatItem.Assistant(t1.text, t1.raw, t1.toolCalls)
        h += ChatItem.ToolResult(t1.toolCalls[0].id, ToolCatalog.HANDSHAKE, "{\"status\":\"attested\"}", false)
        b.complete("SYS", h, ToolCatalog.all)
        val resp = engine.sent[1] as EngineMessage.ToolResponses
        assertEquals("attested", resp.responses.single().response.jsonObject["status"]!!.jsonPrimitive.content)
        // A fresh backend given the same history must replay it into a new conversation.
        val engine2 = FakeEngine(ArrayDeque(listOf(EngineReply("ok", emptyList()))))
        OnDeviceBackend(engine2, nativeTools = true).complete("SYS", h, ToolCatalog.all)
        val replay = engine2.starts.single().second
        assertEquals(2, replay.size)
        assertIs<EngineMessage.User>(replay[0])
        assertEquals(ToolCatalog.HANDSHAKE, (replay[1] as EngineMessage.Model).toolCalls.single().name)
        assertIs<EngineMessage.ToolResponses>(engine2.sent.single())
    }

    @Test
    fun engineErrorsMapToOutcomes() = runBlocking {
        val engine = FakeEngine(ArrayDeque())
        val b = OnDeviceBackend(engine, nativeTools = false)
        engine.failNext = LocalEngineException("no model file imported", recoverable = false)
        assertIs<BackendOutcome.Fatal>(b.complete("S", listOf(ChatItem.User("x")), ToolCatalog.all))
        engine.failNext = IllegalStateException("Input token ids are too long. Exceeding the maximum number of tokens allowed")
        assertIs<BackendOutcome.TranscriptRejected>(b.complete("S", listOf(ChatItem.User("x")), ToolCatalog.all))
        engine.failNext = IOException("boom")
        assertIs<BackendOutcome.Retryable>(b.complete("S", listOf(ChatItem.User("x")), ToolCatalog.all))
        engine.failNext = LocalEngineException("engine busy", recoverable = true)
        assertIs<BackendOutcome.Retryable>(b.complete("S", listOf(ChatItem.User("x")), ToolCatalog.all))
    }
}
