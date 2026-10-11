package dev.zcpmap.agent

import dev.zcpmap.protocol.JsonSchema
import dev.zcpmap.protocol.StrictJsonException
import dev.zcpmap.protocol.StrictJsonParser
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/*
 * Tool calling for models without a native tool-call format (most small on-device models, and any
 * server model whose template lacks tool support). The model is told to emit
 *
 *     <tool_call>{"name": "...", "arguments": {...}}</tool_call>
 *
 * which is the Hermes/Qwen convention many open models were trained on. Tool results go back as
 * <tool_result> blocks inside a user message. Parsing is deliberately tolerant of small-model quirks
 * (missing closing tag, code fences, "parameters" instead of "arguments", arguments as a JSON string)
 * but never tolerant of ambiguity: duplicate keys or non-JSON produce an invalid call that the airlock
 * rejects and the model sees as an error.
 */
object TextToolProtocol {
    const val MAX_CALLS_PER_REPLY = 4

    data class Parsed(val visibleText: String, val reasoning: String?, val calls: List<ToolCallRequest>)

    /**
     * [compact] renders each tool as a one-line signature (about a quarter of the size) for small
     * on-device models with 4k-token windows; the full form embeds the complete JSON Schemas.
     */
    fun instructions(tools: List<ToolSpec>, compact: Boolean = false): String = buildString {
        appendLine("# Calling tools")
        if (compact) {
            appendLine("Tools (name(parameters) - purpose). '?' marks optional parameters:")
            tools.forEach { t -> appendLine("- ${t.name}(${signature(t.schema)}) - ${firstSentence(t.description)}") }
        } else {
            appendLine("You can call these tools. Each entry is {name, description, parameters (JSON Schema)}:")
            tools.forEach { t ->
                append(buildJsonObject {
                    put("name", t.name)
                    put("description", t.description)
                    put("parameters", t.schema.toJson())
                }.toString())
                appendLine()
            }
        }
        appendLine()
        appendLine("To call a tool, reply with one line per call, exactly in this form and nothing else on that line:")
        appendLine("<tool_call>{\"name\": \"tool_name\", \"arguments\": {\"param\": \"value\"}}</tool_call>")
        appendLine("Arguments must be valid JSON and must match the schema exactly (integers without quotes or decimals).")
        appendLine("Results come back in <tool_result> blocks. When you are done, reply with one or two short plain sentences and no tool call.")
    }

    private fun signature(o: JsonSchema.Obj): String = o.properties.entries.joinToString(", ") { (k, v) ->
        k + (if (k in o.required) "" else "?") + ": " + typeOf(v)
    }

    private fun typeOf(s: JsonSchema): String = when (s) {
        is JsonSchema.Str -> {
            val values = s.enum
            val regex = s.pattern
            when {
                values != null -> values.joinToString("|")
                regex != null -> "string ${regex.pattern}"
                else -> "string(max ${s.maxLength})"
            }
        }
        is JsonSchema.Integer -> "int" + if (s.minimum != Long.MIN_VALUE && s.maximum != Long.MAX_VALUE) " ${s.minimum}..${s.maximum}" else ""
        is JsonSchema.Num -> "number"
        is JsonSchema.Bool -> "bool"
        is JsonSchema.Arr -> "[${typeOf(s.items)}]"
        is JsonSchema.Obj -> "{${signature(s)}}"
    }

    private fun firstSentence(d: String): String {
        val end = d.indexOf(". ").let { if (it < 0) d.length else it + 1 }
        return d.substring(0, end).take(160)
    }

    fun renderResults(results: List<ChatItem.ToolResult>): String = results.joinToString("\n") { r ->
        "<tool_result id=\"${r.callId}\" name=\"${r.toolName}\" error=\"${r.isError}\">${r.content}</tool_result>"
    }

    private val THINK = Regex("(?s)<think>(.*?)(</think>|$)")
    private val TAGGED = Regex("(?s)<tool_call>\\s*(.*?)\\s*(</tool_call>|$)")
    private val FENCED = Regex("(?s)```(?:json|tool_call)?\\s*(\\{.*?\\})\\s*```")

    fun parse(raw: String, idPrefix: String): Parsed {
        var text = raw
        val reasoning = THINK.findAll(text).map { it.groupValues[1].trim() }.filter { it.isNotEmpty() }.joinToString("\n").ifEmpty { null }
        text = THINK.replace(text, "")

        val bodies = ArrayList<String>()
        if (text.contains("<tool_call>")) {
            TAGGED.findAll(text).forEach { bodies += it.groupValues[1] }
            text = TAGGED.replace(text, "")
        } else {
            FENCED.findAll(text).forEach { m ->
                val inner = m.groupValues[1]
                if (inner.contains("\"name\"") && (inner.contains("\"arguments\"") || inner.contains("\"parameters\""))) {
                    bodies += inner
                    text = text.replace(m.value, "")
                }
            }
            if (bodies.isEmpty()) {
                val trimmed = text.trim()
                if (trimmed.startsWith("{") && trimmed.endsWith("}") && trimmed.contains("\"name\"")) {
                    bodies += trimmed
                    text = ""
                }
            }
        }
        val calls = bodies.take(MAX_CALLS_PER_REPLY).mapIndexed { i, body -> toCall(body.trim(), "$idPrefix$i") }
        return Parsed(text.trim(), reasoning, calls)
    }

    private fun toCall(body: String, id: String): ToolCallRequest {
        val obj = try {
            StrictJsonParser.parseObject(body)
        } catch (e: StrictJsonException) {
            return ToolCallRequest(id, guessName(body), JsonPrimitive("unparseable tool call JSON: ${e.message}"))
        }
        val name = (obj["name"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: return ToolCallRequest(id, "invalid", JsonPrimitive("tool call has no \"name\""))
        val argsEl: JsonElement = obj["arguments"] ?: obj["parameters"] ?: JsonObject(emptyMap())
        val args: JsonElement = when (argsEl) {
            is JsonObject -> argsEl
            is JsonPrimitive -> if (argsEl.isString) {
                try { StrictJsonParser.parseObject(argsEl.content) } catch (e: StrictJsonException) { JsonPrimitive("arguments are not a JSON object") }
            } else JsonPrimitive("arguments must be a JSON object")
            is JsonArray -> JsonPrimitive("arguments must be a JSON object")
        }
        return ToolCallRequest(id, name, args)
    }

    private fun guessName(body: String): String =
        Regex("\"name\"\\s*:\\s*\"([a-z_]{1,40})\"").find(body)?.groupValues?.get(1) ?: "invalid"
}
