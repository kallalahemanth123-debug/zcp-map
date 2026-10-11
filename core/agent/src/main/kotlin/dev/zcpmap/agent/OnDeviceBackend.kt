package dev.zcpmap.agent

import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/*
 * A language model running on the phone itself. The engine (LiteRT-LM in the app module) is
 * stateful: it keeps the conversation and its KV cache between calls. This backend mirrors what the
 * engine holds and, on each turn, either sends only the new message (fast path) or rebuilds the
 * engine conversation from the kernel's transcript (after a reset, or when the transcript diverged).
 */

data class EngineToolCall(val name: String, val arguments: JsonObject)
data class EngineToolResponse(val name: String, val response: JsonElement)

sealed interface EngineMessage {
    data class User(val text: String) : EngineMessage
    data class Model(val text: String, val toolCalls: List<EngineToolCall>) : EngineMessage
    data class ToolResponses(val responses: List<EngineToolResponse>) : EngineMessage
}

data class EngineReply(val text: String, val toolCalls: List<EngineToolCall>)

/** Thrown by engines. [recoverable] = worth retrying (e.g. busy); otherwise operator action is needed. */
class LocalEngineException(message: String, val recoverable: Boolean, cause: Throwable? = null) : Exception(message, cause)

interface LocalLlmEngine : AutoCloseable {
    val modelName: String

    /** Replaces the current conversation. [tools] is non-null only when native tool calling is used. */
    suspend fun startConversation(systemPrompt: String, history: List<EngineMessage>, tools: List<ToolSpec>?)

    suspend fun send(message: EngineMessage): EngineReply
}

class OnDeviceBackend(
    private val engine: LocalLlmEngine,
    /** True only for models with a tool-calling chat template (e.g. FunctionGemma, Gemma 3n). */
    private val nativeTools: Boolean,
    override val contextBudgetChars: Int = 12_000,
) : LlmBackend {
    private var mirroredSystem: String? = null
    private var mirrored: List<ChatItem>? = null
    private var callCounter = 0L

    override val label: String get() = "On-device · ${engine.modelName}"
    override val prefersCompactPrompt: Boolean get() = true

    override suspend fun complete(system: String, history: List<ChatItem>, tools: List<ToolSpec>): BackendOutcome {
        if (history.isEmpty() || history.last() is ChatItem.Assistant) {
            return BackendOutcome.TranscriptRejected("transcript must end with a user message or tool results")
        }
        val fullSystem = if (nativeTools) system else system + "\n\n" + TextToolProtocol.instructions(tools, compact = true)
        // Split into: what the engine must already hold (prefix) + the one message we send now.
        val sendCount = if (nativeTools) trailingSameKind(history) else history.size - 1 - history.indexOfLast { it is ChatItem.Assistant }
        val prefix = history.subList(0, history.size - sendCount)
        val pending = history.subList(history.size - sendCount, history.size)
        return try {
            if (mirroredSystem != fullSystem || mirrored != prefix) {
                engine.startConversation(fullSystem, toEngineMessages(prefix), if (nativeTools) tools else null)
                mirroredSystem = fullSystem
                mirrored = prefix.toList()
            }
            val reply = engine.send(toEngineMessage(pending))
            val turn = toTurn(reply)
            mirrored = history.toList() + ChatItem.Assistant(turn.text, turn.raw, turn.toolCalls)
            BackendOutcome.Success(turn)
        } catch (e: CancellationException) {
            invalidate()
            throw e
        } catch (e: LocalEngineException) {
            invalidate()
            if (e.recoverable) BackendOutcome.Retryable(e.message ?: "engine busy") else BackendOutcome.Fatal(e.message ?: "on-device model failed")
        } catch (e: Exception) {
            invalidate()
            val msg = e.message ?: e.javaClass.simpleName
            if (msg.contains("token", ignoreCase = true) && (msg.contains("exceed", true) || msg.contains("max", true) || msg.contains("context", true))) {
                BackendOutcome.TranscriptRejected("model context full: $msg")
            } else {
                BackendOutcome.Retryable("on-device engine error: $msg")
            }
        }
    }

    override fun reset() = invalidate()

    override fun close() {
        invalidate()
        engine.close()
    }

    private fun invalidate() {
        mirroredSystem = null
        mirrored = null
    }

    private fun trailingSameKind(h: List<ChatItem>): Int {
        val last = h.last()
        var n = 0
        for (i in h.indices.reversed()) {
            val it = h[i]
            if ((last is ChatItem.User && it is ChatItem.User) || (last is ChatItem.ToolResult && it is ChatItem.ToolResult)) n++ else break
        }
        return n
    }

    private fun toEngineMessage(items: List<ChatItem>): EngineMessage {
        if (nativeTools && items.all { it is ChatItem.ToolResult }) {
            return EngineMessage.ToolResponses(items.map { r ->
                r as ChatItem.ToolResult
                EngineToolResponse(r.toolName, parseResult(r.content))
            })
        }
        // Text protocol (or user text): one user message with tool results first, then any user text.
        val results = items.filterIsInstance<ChatItem.ToolResult>()
        val texts = items.filterIsInstance<ChatItem.User>().map { it.text }
        val parts = ArrayList<String>()
        if (results.isNotEmpty()) parts += TextToolProtocol.renderResults(results)
        parts += texts
        return EngineMessage.User(parts.joinToString("\n\n"))
    }

    private fun toEngineMessages(items: List<ChatItem>): List<EngineMessage> {
        val out = ArrayList<EngineMessage>()
        var i = 0
        while (i < items.size) {
            when (val it = items[i]) {
                is ChatItem.Assistant -> {
                    out += if (nativeTools) {
                        EngineMessage.Model(it.text, it.toolCalls.mapNotNull { c -> (c.arguments as? JsonObject)?.let { a -> EngineToolCall(c.name, a) } })
                    } else {
                        EngineMessage.Model(it.raw, emptyList())
                    }
                    i++
                }
                else -> {
                    var j = i
                    while (j < items.size && items[j] !is ChatItem.Assistant) j++
                    val group = items.subList(i, j)
                    if (nativeTools) {
                        // Keep tool responses and user text as separate engine messages.
                        var k = 0
                        while (k < group.size) {
                            var m = k
                            while (m < group.size && group[m]::class == group[k]::class) m++
                            out += toEngineMessage(group.subList(k, m))
                            k = m
                        }
                    } else {
                        out += toEngineMessage(group)
                    }
                    i = j
                }
            }
        }
        return out
    }

    private fun toTurn(reply: EngineReply): AssistantTurn {
        val batch = "d${callCounter++}_"
        val parsed = TextToolProtocol.parse(reply.text, batch)
        val calls = if (reply.toolCalls.isNotEmpty()) {
            reply.toolCalls.take(TextToolProtocol.MAX_CALLS_PER_REPLY).mapIndexed { i, c -> ToolCallRequest("$batch$i", c.name, c.arguments) }
        } else parsed.calls
        return AssistantTurn(
            text = parsed.visibleText,
            raw = reply.text,
            reasoning = parsed.reasoning,
            toolCalls = calls,
            stop = if (calls.isNotEmpty()) StopKind.TOOL_CALLS else StopKind.END_TURN,
            inputTokens = 0,
            outputTokens = 0,
        )
    }

    private fun parseResult(content: String): JsonElement = try {
        dev.zcpmap.protocol.StrictJsonParser.parse(content, dev.zcpmap.protocol.StrictJsonParser.Limits(maxBytes = 256 * 1024))
    } catch (e: Exception) {
        JsonPrimitive(content)
    }
}
