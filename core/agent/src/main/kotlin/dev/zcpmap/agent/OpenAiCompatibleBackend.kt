package dev.zcpmap.agent

import dev.zcpmap.protocol.StrictJsonException
import dev.zcpmap.protocol.StrictJsonParser
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.io.IOException

/**
 * The operator's own model server on the local network, spoken to with the de-facto standard
 * `POST /v1/chat/completions` format implemented by Ollama, LM Studio, llama.cpp `llama-server`,
 * vLLM and LocalAI.
 *
 * Notes on real servers:
 *  - Ollama ignores `tool_choice` (we never send it) and returns tool-call arguments as a JSON string.
 *  - Ollama's default context window is small; set OLLAMA_CONTEXT_LENGTH=16384 (or more) on the server,
 *    otherwise long prompts are silently truncated.
 *  - Models whose template lacks tool support make the server answer 400; we then switch this
 *    backend to the text tool protocol automatically.
 */
data class LocalServerConfig(
    /** e.g. http://192.168.1.20:11434 (Ollama), http://192.168.1.20:1234 (LM Studio), https://ai.my-home.net */
    val baseUrl: String,
    /** Model name exactly as the server knows it, e.g. "qwen2.5:7b-instruct". */
    val model: String,
    /** Optional bearer token if your server requires one. */
    val token: String? = null,
    /** Use the server's native tool calling; false = text tool protocol (works with any instruct model). */
    val nativeTools: Boolean = true,
    val temperature: Double = 0.2,
    val maxOutputTokens: Int = 1024,
    val contextBudgetChars: Int = 48_000,
)

class OpenAiCompatibleBackend(
    private val config: LocalServerConfig,
    private val http: HttpTransport = UrlConnectionTransport(),
) : LlmBackend {
    @Volatile private var nativeTools = config.nativeTools
    private var callCounter = 0L

    override val label: String get() = "Server · ${config.model}"
    override val contextBudgetChars: Int get() = config.contextBudgetChars
    override val prefersCompactPrompt: Boolean get() = false

    val endpoint: String = chatCompletionsUrl(config.baseUrl)
    val usingNativeTools: Boolean get() = nativeTools

    override suspend fun complete(system: String, history: List<ChatItem>, tools: List<ToolSpec>): BackendOutcome {
        val first = request(system, history, tools)
        if (first is BackendOutcome.TranscriptRejected && nativeTools && looksLikeNoToolSupport(first.detail)) {
            nativeTools = false
            return request(system, history, tools)
        }
        return first
    }

    private suspend fun request(system: String, history: List<ChatItem>, tools: List<ToolSpec>): BackendOutcome {
        val body = buildRequest(system, history, tools).toString()
        val headers = buildMap {
            put("content-type", "application/json")
            put("accept", "application/json")
            config.token?.takeIf { it.isNotBlank() }?.let { put("authorization", "Bearer $it") }
        }
        val reply = try {
            http.postJson(endpoint, headers, body)
        } catch (e: CancellationException) {
            throw e
        } catch (e: RefusedEndpointException) {
            return BackendOutcome.Fatal(e.message ?: "endpoint refused by local-network policy")
        } catch (e: IOException) {
            return BackendOutcome.Retryable("cannot reach ${config.baseUrl}: ${e.javaClass.simpleName} ${e.message ?: ""}".trim())
        }
        val detail = errorDetail(reply.body)
        return when (reply.status) {
            200 -> parseResponse(reply.body)
            408, 409, 425, 429, 500, 502, 503, 504 -> BackendOutcome.Retryable("server ${reply.status}: $detail", reply.retryAfterSeconds?.times(1000))
            400, 413, 422 -> BackendOutcome.TranscriptRejected("server ${reply.status}: $detail")
            401, 403 -> BackendOutcome.Fatal("server refused the token (${reply.status}): $detail")
            404 -> BackendOutcome.Fatal("not found (${reply.status}) — check the server URL and model name \"${config.model}\": $detail")
            else -> BackendOutcome.Fatal("server ${reply.status}: $detail")
        }
    }

    fun buildRequest(system: String, history: List<ChatItem>, tools: List<ToolSpec>): JsonObject = buildJsonObject {
        val native = nativeTools
        put("model", config.model)
        put("stream", false)
        put("temperature", config.temperature)
        put("max_tokens", config.maxOutputTokens)
        val systemText = if (native) system else system + "\n\n" + TextToolProtocol.instructions(tools)
        put("messages", buildJsonArray {
            add(buildJsonObject { put("role", "system"); put("content", systemText) })
            var i = 0
            while (i < history.size) {
                when (val item = history[i]) {
                    is ChatItem.User -> add(buildJsonObject { put("role", "user"); put("content", item.text) })
                    is ChatItem.Assistant -> add(buildJsonObject {
                        put("role", "assistant")
                        if (native) {
                            put("content", item.text)
                            if (item.toolCalls.isNotEmpty()) put("tool_calls", buildJsonArray {
                                item.toolCalls.forEach { c ->
                                    add(buildJsonObject {
                                        put("id", c.id); put("type", "function")
                                        put("function", buildJsonObject { put("name", c.name); put("arguments", c.arguments.toString()) })
                                    })
                                }
                            })
                        } else {
                            put("content", item.raw)
                        }
                    })
                    is ChatItem.ToolResult -> if (native) {
                        add(buildJsonObject { put("role", "tool"); put("tool_call_id", item.callId); put("content", item.content) })
                    } else {
                        // Group consecutive results into one user message.
                        val group = ArrayList<ChatItem.ToolResult>()
                        var j = i
                        while (j < history.size && history[j] is ChatItem.ToolResult) { group += history[j] as ChatItem.ToolResult; j++ }
                        add(buildJsonObject { put("role", "user"); put("content", TextToolProtocol.renderResults(group)) })
                        i = j - 1
                    }
                }
                i++
            }
        })
        if (native && tools.isNotEmpty()) put("tools", ToolCatalog.openAiTools(tools))
    }

    private fun parseResponse(body: String): BackendOutcome {
        val obj = try {
            StrictJsonParser.parseObject(body, LIMITS)
        } catch (e: StrictJsonException) {
            return BackendOutcome.Retryable("malformed server response: ${e.message}")
        }
        val choice = (obj["choices"] as? JsonArray)?.firstOrNull() as? JsonObject
            ?: return BackendOutcome.Retryable("server response has no choices")
        val msg = choice["message"] as? JsonObject ?: return BackendOutcome.Retryable("server response has no message")
        val content = (msg["content"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull ?: ""
        val serverReasoning = listOf("reasoning_content", "reasoning").firstNotNullOfOrNull { k ->
            (msg[k] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull?.takeIf { it.isNotBlank() }
        }
        val batch = "c${callCounter++}_"
        val nativeCalls = (msg["tool_calls"] as? JsonArray).orEmpty().mapIndexedNotNull { i, el ->
            val tc = el as? JsonObject ?: return@mapIndexedNotNull null
            val fn = tc["function"] as? JsonObject ?: return@mapIndexedNotNull null
            val name = (fn["name"] as? JsonPrimitive)?.contentOrNull ?: "invalid"
            val id = (tc["id"] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() && it.length <= 64 } ?: "$batch$i"
            ToolCallRequest(id, name, decodeArguments(fn["arguments"]))
        }.take(TextToolProtocol.MAX_CALLS_PER_REPLY)
        // Even in native mode, some servers leave <tool_call> markup in the text instead of parsing it.
        val parsed = TextToolProtocol.parse(content, batch)
        val calls = nativeCalls.ifEmpty { parsed.calls }
        val finish = (choice["finish_reason"] as? JsonPrimitive)?.contentOrNull
        val usage = obj["usage"] as? JsonObject
        fun n(k: String) = (usage?.get(k) as? JsonPrimitive)?.longOrNull ?: 0
        return BackendOutcome.Success(
            AssistantTurn(
                text = parsed.visibleText,
                raw = content,
                reasoning = listOfNotNull(serverReasoning, parsed.reasoning).joinToString("\n").ifEmpty { null },
                toolCalls = calls,
                stop = when {
                    calls.isNotEmpty() -> StopKind.TOOL_CALLS
                    finish == "length" -> StopKind.MAX_TOKENS
                    else -> StopKind.END_TURN
                },
                inputTokens = n("prompt_tokens"),
                outputTokens = n("completion_tokens"),
            ),
        )
    }

    private fun decodeArguments(el: JsonElement?): JsonElement = when (el) {
        null, JsonNull -> JsonObject(emptyMap())
        is JsonObject -> el
        is JsonPrimitive -> if (el.isString) {
            if (el.content.isBlank()) JsonObject(emptyMap())
            else try { StrictJsonParser.parseObject(el.content) } catch (e: StrictJsonException) { JsonPrimitive("arguments are not valid JSON: ${e.message}") }
        } else JsonPrimitive("arguments must be a JSON object")
        is JsonArray -> JsonPrimitive("arguments must be a JSON object")
    }

    private fun errorDetail(body: String): String = try {
        val o = StrictJsonParser.parseObject(body, StrictJsonParser.Limits(maxBytes = 256 * 1024))
        when (val e = o["error"]) {
            is JsonObject -> (e["message"] as? JsonPrimitive)?.contentOrNull ?: e.toString()
            is JsonPrimitive -> e.content
            else -> body
        }.take(300)
    } catch (_: Exception) {
        body.take(300)
    }

    private fun looksLikeNoToolSupport(detail: String): Boolean {
        val d = detail.lowercase()
        return d.contains("tool") && (d.contains("not support") || d.contains("unsupported") || d.contains("does not support"))
    }

    companion object {
        private val LIMITS = StrictJsonParser.Limits(
            maxBytes = UrlConnectionTransport.MAX_RESPONSE_BYTES, maxDepth = 32,
            maxStringChars = 2 * 1024 * 1024, maxObjectKeys = 512, maxArrayItems = 4096,
        )

        /** Accepts ".../v1", ".../v1/", or a bare host:port and returns the chat-completions URL. */
        fun chatCompletionsUrl(baseUrl: String): String {
            val b = baseUrl.trim().trimEnd('/')
            return when {
                b.endsWith("/chat/completions") -> b
                b.endsWith("/v1") -> "$b/chat/completions"
                else -> "$b/v1/chat/completions"
            }
        }
    }
}

private fun JsonArray?.orEmpty(): List<JsonElement> = this ?: emptyList()
