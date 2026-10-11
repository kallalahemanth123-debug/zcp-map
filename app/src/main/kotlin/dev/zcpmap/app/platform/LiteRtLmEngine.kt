package dev.zcpmap.app.platform

import com.google.ai.edge.litertlm.Backend
import com.google.ai.edge.litertlm.Content
import com.google.ai.edge.litertlm.Contents
import com.google.ai.edge.litertlm.Conversation
import com.google.ai.edge.litertlm.ConversationConfig
import com.google.ai.edge.litertlm.Engine
import com.google.ai.edge.litertlm.EngineConfig
import com.google.ai.edge.litertlm.Message
import com.google.ai.edge.litertlm.OpenApiTool
import com.google.ai.edge.litertlm.SamplerConfig
import com.google.ai.edge.litertlm.ToolCall
import com.google.ai.edge.litertlm.tool
import dev.zcpmap.agent.EngineMessage
import dev.zcpmap.agent.EngineReply
import dev.zcpmap.agent.EngineToolCall
import dev.zcpmap.agent.LocalEngineException
import dev.zcpmap.agent.LocalLlmEngine
import dev.zcpmap.agent.ToolSpec
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * On-device language model through Google's LiteRT-LM (com.google.ai.edge.litertlm), the
 * recommended successor of the MediaPipe LLM Inference API. Works fully offline with a `.litertlm`
 * model file the operator imports once (e.g. Gemma3-1B-IT or Qwen2.5-1.5B-Instruct from the
 * Hugging Face "litert-community" organisation).
 *
 * All native calls run on one dedicated thread: the engine is not documented as thread-safe and
 * `initialize()` can take ~10 s. Cancelling the calling coroutine asks the engine to stop generating.
 */
class LiteRtLmEngine(
    private val modelFile: File,
    private val useGpu: Boolean,
    private val maxNumTokens: Int,
    private val cacheDir: File,
) : LocalLlmEngine {
    override val modelName: String = modelFile.nameWithoutExtension.take(40)

    private val executor: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "zcp-llm").apply { isDaemon = true } }
    @Volatile private var engine: Engine? = null
    @Volatile private var conversation: Conversation? = null

    override suspend fun startConversation(systemPrompt: String, history: List<EngineMessage>, tools: List<ToolSpec>?) {
        onEngineThread {
            val e = ensureEngine()
            conversation?.close()
            conversation = null
            conversation = e.createConversation(
                ConversationConfig(
                    systemInstruction = Contents.of(systemPrompt),
                    initialMessages = history.map(::toMessage),
                    tools = tools?.map { tool(SpecTool(it)) } ?: emptyList(),
                    automaticToolCalling = false,
                    samplerConfig = SamplerConfig(topK = 40, topP = 0.95, temperature = 0.3),
                ),
            )
        }
    }

    override suspend fun send(message: EngineMessage): EngineReply = onEngineThread(cancel = { conversation?.cancelProcess() }) {
        val c = conversation ?: throw LocalEngineException("no active conversation", recoverable = true)
        val reply = c.sendMessage(toMessage(message))
        EngineReply(
            text = reply.contents.contents.filterIsInstance<Content.Text>().joinToString("") { it.text },
            toolCalls = reply.toolCalls.map { EngineToolCall(it.name, mapToJson(it.arguments)) },
        )
    }

    override fun close() {
        executor.execute {
            try { conversation?.close() } catch (_: Exception) {}
            try { engine?.close() } catch (_: Exception) {}
            conversation = null
            engine = null
        }
        executor.shutdown()
    }

    // ------------------------------------------------------------------ internals

    private fun ensureEngine(): Engine {
        engine?.let { return it }
        if (!modelFile.isFile) {
            throw LocalEngineException("No on-device model imported. Open SETUP and import a .litertlm file.", recoverable = false)
        }
        val e = try {
            Engine(
                EngineConfig(
                    modelPath = modelFile.absolutePath,
                    backend = if (useGpu) Backend.GPU() else Backend.CPU(),
                    maxNumTokens = maxNumTokens,
                    cacheDir = cacheDir.absolutePath,
                ),
            ).also { it.initialize() }
        } catch (t: Throwable) {
            throw LocalEngineException("Could not load ${modelFile.name}: ${t.message ?: t.javaClass.simpleName}. " +
                "Check that it is a .litertlm file and that the phone has enough free memory; try CPU instead of GPU.", recoverable = false, t)
        }
        engine = e
        return e
    }

    private suspend fun <T> onEngineThread(cancel: () -> Unit = {}, block: () -> T): T = suspendCancellableCoroutine { cont ->
        val future = executor.submit {
            try {
                val v = block()
                if (cont.isActive) cont.resume(v)
            } catch (t: Throwable) {
                if (cont.isActive) cont.resumeWithException(t)
            }
        }
        cont.invokeOnCancellation {
            cancel()
            future.cancel(false)
        }
    }

    private fun toMessage(m: EngineMessage): Message = when (m) {
        is EngineMessage.User -> Message.user(m.text)
        is EngineMessage.Model -> Message.model(
            contents = Contents.of(if (m.text.isEmpty()) emptyList() else listOf(Content.Text(m.text))),
            toolCalls = m.toolCalls.map { ToolCall(it.name, jsonToMap(it.arguments)) },
        )
        is EngineMessage.ToolResponses -> Message.tool(
            Contents.of(m.responses.map { Content.ToolResponse(it.name, jsonToAny(it.response)) }),
        )
    }

    /** Hands our schema to LiteRT-LM verbatim; execution stays with the airlock (automaticToolCalling = false). */
    private class SpecTool(private val spec: ToolSpec) : OpenApiTool {
        override fun getToolDescriptionJsonString(): String = buildJsonObject {
            put("name", spec.name)
            put("description", spec.description)
            put("parameters", spec.schema.toJson())
        }.toString()

        override fun execute(paramsJsonString: String): String =
            throw IllegalStateException("tools are executed by the airlock, never by the engine")
    }

    companion object {
        fun jsonToMap(o: JsonObject): Map<String, Any?> = o.mapValues { (_, v) -> jsonToAny(v) }

        fun jsonToAny(e: JsonElement): Any? = when (e) {
            JsonNull -> null
            is JsonObject -> jsonToMap(e)
            is JsonArray -> e.map { jsonToAny(it) }
            is JsonPrimitive -> when {
                e.isString -> e.content
                e.booleanOrNull != null -> e.booleanOrNull
                e.longOrNull != null -> e.longOrNull
                else -> e.doubleOrNull ?: e.content
            }
        }

        fun mapToJson(m: Map<String, Any?>): JsonObject = JsonObject(m.mapValues { (_, v) -> anyToJson(v) })

        /** Whole-number doubles become integers, so `1000.0` from the engine passes integer schemas. */
        fun anyToJson(v: Any?): JsonElement = when (v) {
            null -> JsonNull
            is JsonElement -> v
            is String -> JsonPrimitive(v)
            is Boolean -> JsonPrimitive(v)
            is Map<*, *> -> JsonObject(v.entries.associate { (k, x) -> k.toString() to anyToJson(x) })
            is Iterable<*> -> JsonArray(v.map { anyToJson(it) })
            is Array<*> -> JsonArray(v.map { anyToJson(it) })
            is Number -> {
                val d = v.toDouble()
                if (!d.isNaN() && !d.isInfinite() && d == Math.floor(d) && kotlin.math.abs(d) < 9.0e15) JsonPrimitive(d.toLong())
                else JsonPrimitive(d)
            }
            else -> JsonPrimitive(v.toString())
        }
    }
}
