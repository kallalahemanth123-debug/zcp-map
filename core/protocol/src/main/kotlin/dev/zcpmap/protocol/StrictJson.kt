package dev.zcpmap.protocol

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/*
 * Security-hardened JSON handling shared by every layer that touches peer- or LLM-authored JSON.
 *
 *  - StrictJsonParser: RFC 8259 parser that REJECTS duplicate keys (prevents parser-differential
 *    attacks where a signer and a verifier see different values), enforces depth/size/string
 *    limits, rejects NaN/Infinity, lone surrogates and trailing garbage.
 *  - CanonicalJson: RFC 8785 (JCS) serialization restricted to integers (floats are rejected,
 *    which sidesteps ECMAScript number formatting entirely). Used as the exact signing input.
 *  - JsonSchema: a closed subset of JSON Schema 2020-12 with fail-closed validation. The same
 *    object renders the schema sent to the agent model (tool definitions) and validates inputs.
 */

class StrictJsonException(message: String) : Exception(message)

object StrictJsonParser {
    data class Limits(
        val maxBytes: Int = 64 * 1024,
        val maxDepth: Int = 16,
        val maxStringChars: Int = 16 * 1024,
        val maxObjectKeys: Int = 256,
        val maxArrayItems: Int = 1024,
    )

    fun parse(text: String, limits: Limits = Limits()): JsonElement {
        if (text.length > limits.maxBytes) throw StrictJsonException("json exceeds ${limits.maxBytes} chars")
        val p = Parser(text, limits)
        p.skipWs()
        val v = p.value(0)
        p.skipWs()
        if (p.pos != text.length) throw StrictJsonException("trailing data at ${p.pos}")
        return v
    }

    fun parseObject(text: String, limits: Limits = Limits()): JsonObject =
        parse(text, limits) as? JsonObject ?: throw StrictJsonException("top-level value must be an object")

    private class Parser(val s: String, val lim: Limits) {
        var pos = 0

        fun skipWs() {
            while (pos < s.length) {
                val c = s[pos]
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++ else break
            }
        }

        fun value(depth: Int): JsonElement {
            if (depth > lim.maxDepth) throw StrictJsonException("max depth exceeded")
            if (pos >= s.length) throw StrictJsonException("unexpected end")
            return when (val c = s[pos]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> JsonPrimitive(string())
                't' -> literal("true", JsonPrimitive(true))
                'f' -> literal("false", JsonPrimitive(false))
                'n' -> literal("null", JsonNull)
                else -> if (c == '-' || c in '0'..'9') number() else throw StrictJsonException("unexpected '$c' at $pos")
            }
        }

        fun literal(word: String, v: JsonElement): JsonElement {
            if (!s.startsWith(word, pos)) throw StrictJsonException("invalid literal at $pos")
            pos += word.length
            return v
        }

        fun obj(depth: Int): JsonObject {
            pos++ // {
            val map = LinkedHashMap<String, JsonElement>()
            skipWs()
            if (pos < s.length && s[pos] == '}') { pos++; return JsonObject(map) }
            while (true) {
                skipWs()
                if (pos >= s.length || s[pos] != '"') throw StrictJsonException("expected key at $pos")
                val key = string()
                if (map.containsKey(key)) throw StrictJsonException("duplicate key '$key'")
                skipWs()
                expect(':')
                skipWs()
                map[key] = value(depth + 1)
                if (map.size > lim.maxObjectKeys) throw StrictJsonException("too many keys")
                skipWs()
                if (pos >= s.length) throw StrictJsonException("unterminated object")
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return JsonObject(map) }
                    else -> throw StrictJsonException("expected , or } at $pos")
                }
            }
        }

        fun arr(depth: Int): JsonArray {
            pos++ // [
            val items = ArrayList<JsonElement>()
            skipWs()
            if (pos < s.length && s[pos] == ']') { pos++; return JsonArray(items) }
            while (true) {
                skipWs()
                items += value(depth + 1)
                if (items.size > lim.maxArrayItems) throw StrictJsonException("too many array items")
                skipWs()
                if (pos >= s.length) throw StrictJsonException("unterminated array")
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return JsonArray(items) }
                    else -> throw StrictJsonException("expected , or ] at $pos")
                }
            }
        }

        fun expect(c: Char) {
            if (pos >= s.length || s[pos] != c) throw StrictJsonException("expected '$c' at $pos")
            pos++
        }

        fun string(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                if (pos >= s.length) throw StrictJsonException("unterminated string")
                val c = s[pos++]
                when {
                    c == '"' -> break
                    c == '\\' -> {
                        if (pos >= s.length) throw StrictJsonException("bad escape")
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000C'); 'n' -> sb.append('\n')
                            'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) throw StrictJsonException("bad \\u escape")
                                val code = s.substring(pos, pos + 4).toIntOrNull(16)
                                    ?: throw StrictJsonException("bad \\u escape")
                                pos += 4
                                sb.append(code.toChar())
                            }
                            else -> throw StrictJsonException("invalid escape \\$e")
                        }
                    }
                    c.code < 0x20 -> throw StrictJsonException("raw control char in string")
                    else -> sb.append(c)
                }
                if (sb.length > lim.maxStringChars) throw StrictJsonException("string too long")
            }
            val out = sb.toString()
            // Reject lone surrogates: they canonicalize inconsistently across implementations.
            var i = 0
            while (i < out.length) {
                val ch = out[i]
                if (Character.isHighSurrogate(ch)) {
                    if (i + 1 >= out.length || !Character.isLowSurrogate(out[i + 1])) throw StrictJsonException("lone surrogate")
                    i += 2; continue
                }
                if (Character.isLowSurrogate(ch)) throw StrictJsonException("lone surrogate")
                i++
            }
            return out
        }

        fun number(): JsonPrimitive {
            val start = pos
            if (s[pos] == '-') pos++
            if (pos >= s.length) throw StrictJsonException("bad number")
            if (s[pos] == '0') {
                pos++
            } else if (s[pos] in '1'..'9') {
                while (pos < s.length && s[pos] in '0'..'9') pos++
            } else throw StrictJsonException("bad number")
            var isInt = true
            if (pos < s.length && s[pos] == '.') {
                isInt = false; pos++
                if (pos >= s.length || s[pos] !in '0'..'9') throw StrictJsonException("bad fraction")
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            if (pos < s.length && (s[pos] == 'e' || s[pos] == 'E')) {
                isInt = false; pos++
                if (pos < s.length && (s[pos] == '+' || s[pos] == '-')) pos++
                if (pos >= s.length || s[pos] !in '0'..'9') throw StrictJsonException("bad exponent")
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            val lit = s.substring(start, pos)
            if (lit.length > 32) throw StrictJsonException("number literal too long")
            return if (isInt) {
                JsonPrimitive(lit.toLongOrNull() ?: throw StrictJsonException("integer out of 64-bit range"))
            } else {
                val d = lit.toDouble()
                if (d.isNaN() || d.isInfinite()) throw StrictJsonException("non-finite number")
                JsonPrimitive(d)
            }
        }
    }
}

object CanonicalJson {
    /** RFC 8785 canonical form. Only integral numbers are allowed in signed documents. */
    fun encode(e: JsonElement): String = StringBuilder().also { write(e, it) }.toString()

    fun encodeToBytes(e: JsonElement): ByteArray = encode(e).toByteArray(Charsets.UTF_8)

    private fun write(e: JsonElement, sb: StringBuilder) {
        when (e) {
            JsonNull -> sb.append("null")
            is JsonPrimitive -> when {
                e.isString -> writeString(e.content, sb)
                e.booleanOrNull != null -> sb.append(e.content)
                e.longOrNull != null -> sb.append(e.longOrNull.toString())
                else -> throw StrictJsonException("non-integer number '${e.content}' is not allowed in canonical JSON")
            }
            is JsonArray -> {
                sb.append('[')
                e.forEachIndexed { i, v -> if (i > 0) sb.append(','); write(v, sb) }
                sb.append(']')
            }
            is JsonObject -> {
                sb.append('{')
                // JCS orders keys by UTF-16 code units, which is exactly Kotlin String.compareTo.
                e.keys.sorted().forEachIndexed { i, k ->
                    if (i > 0) sb.append(',')
                    writeString(k, sb)
                    sb.append(':')
                    write(e.getValue(k), sb)
                }
                sb.append('}')
            }
        }
    }

    private fun writeString(s: String, sb: StringBuilder) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        sb.append('"')
    }
}

// --------------------------------------------------------------------------------------
// Closed JSON Schema subset
// --------------------------------------------------------------------------------------

sealed class JsonSchema {
    abstract val description: String?
    abstract fun toJson(): JsonObject

    data class Str(
        override val description: String? = null,
        val minLength: Int = 0,
        val maxLength: Int = 256,
        val pattern: Regex? = null,
        val enum: List<String>? = null,
    ) : JsonSchema() {
        override fun toJson() = buildJsonObject {
            put("type", "string")
            description?.let { put("description", it) }
            if (enum != null) {
                put("enum", buildJsonArray { enum.forEach { add(JsonPrimitive(it)) } })
            } else {
                put("minLength", minLength)
                put("maxLength", maxLength)
                pattern?.let { put("pattern", it.pattern) }
            }
        }
    }

    data class Integer(
        override val description: String? = null,
        val minimum: Long = Long.MIN_VALUE,
        val maximum: Long = Long.MAX_VALUE,
    ) : JsonSchema() {
        override fun toJson() = buildJsonObject {
            put("type", "integer")
            description?.let { put("description", it) }
            if (minimum != Long.MIN_VALUE) put("minimum", minimum)
            if (maximum != Long.MAX_VALUE) put("maximum", maximum)
        }
    }

    data class Num(
        override val description: String? = null,
        val minimum: Double = -Double.MAX_VALUE,
        val maximum: Double = Double.MAX_VALUE,
    ) : JsonSchema() {
        override fun toJson() = buildJsonObject {
            put("type", "number")
            description?.let { put("description", it) }
            if (minimum != -Double.MAX_VALUE) put("minimum", minimum)
            if (maximum != Double.MAX_VALUE) put("maximum", maximum)
        }
    }

    data class Bool(override val description: String? = null) : JsonSchema() {
        override fun toJson() = buildJsonObject {
            put("type", "boolean")
            description?.let { put("description", it) }
        }
    }

    data class Arr(
        val items: JsonSchema,
        override val description: String? = null,
        val minItems: Int = 0,
        val maxItems: Int = 32,
    ) : JsonSchema() {
        override fun toJson() = buildJsonObject {
            put("type", "array")
            description?.let { put("description", it) }
            put("items", items.toJson())
            put("minItems", minItems)
            put("maxItems", maxItems)
        }
    }

    /** Objects are always closed: additionalProperties=false is non-negotiable. */
    data class Obj(
        val properties: Map<String, JsonSchema>,
        val required: Set<String>,
        override val description: String? = null,
    ) : JsonSchema() {
        init {
            require(properties.keys.containsAll(required)) { "required keys must be declared" }
        }

        override fun toJson() = buildJsonObject {
            put("type", "object")
            description?.let { put("description", it) }
            put("properties", buildJsonObject { properties.forEach { (k, v) -> put(k, v.toJson()) } })
            put("required", buildJsonArray { required.sorted().forEach { add(JsonPrimitive(it)) } })
            put("additionalProperties", false)
        }
    }
}

sealed interface SchemaResult {
    data object Valid : SchemaResult
    data class Invalid(val path: String, val reason: String) : SchemaResult
}

object SchemaValidator {
    fun validate(schema: JsonSchema, value: JsonElement, path: String = "$"): SchemaResult {
        return when (schema) {
            is JsonSchema.Str -> {
                val p = value as? JsonPrimitive
                if (p == null || !p.isString) return SchemaResult.Invalid(path, "expected string")
                val s = p.content
                if (schema.enum != null) {
                    return if (s in schema.enum) SchemaResult.Valid else SchemaResult.Invalid(path, "value not in enum")
                }
                if (s.length < schema.minLength || s.length > schema.maxLength) {
                    return SchemaResult.Invalid(path, "length ${s.length} outside [${schema.minLength}, ${schema.maxLength}]")
                }
                if (schema.pattern != null && !schema.pattern.matches(s)) {
                    return SchemaResult.Invalid(path, "does not match ${schema.pattern.pattern}")
                }
                SchemaResult.Valid
            }
            is JsonSchema.Integer -> {
                val p = value as? JsonPrimitive
                val v = (if (p != null && !p.isString) p.longOrNull else null)
                    ?: return SchemaResult.Invalid(path, "expected integer")
                if (v < schema.minimum || v > schema.maximum) {
                    SchemaResult.Invalid(path, "integer $v outside [${schema.minimum}, ${schema.maximum}]")
                } else SchemaResult.Valid
            }
            is JsonSchema.Num -> {
                val p = value as? JsonPrimitive
                val v = (if (p != null && !p.isString && p.booleanOrNull == null) p.content.toDoubleOrNull() else null)
                    ?: return SchemaResult.Invalid(path, "expected number")
                if (v.isNaN() || v < schema.minimum || v > schema.maximum) {
                    SchemaResult.Invalid(path, "number $v outside [${schema.minimum}, ${schema.maximum}]")
                } else SchemaResult.Valid
            }
            is JsonSchema.Bool -> {
                val p = value as? JsonPrimitive
                if (p != null && !p.isString && p.booleanOrNull != null) SchemaResult.Valid
                else SchemaResult.Invalid(path, "expected boolean")
            }
            is JsonSchema.Arr -> {
                val a = value as? JsonArray ?: return SchemaResult.Invalid(path, "expected array")
                if (a.size < schema.minItems || a.size > schema.maxItems) {
                    return SchemaResult.Invalid(path, "array size ${a.size} outside [${schema.minItems}, ${schema.maxItems}]")
                }
                a.forEachIndexed { i, item ->
                    val r = validate(schema.items, item, "$path[$i]")
                    if (r is SchemaResult.Invalid) return r
                }
                SchemaResult.Valid
            }
            is JsonSchema.Obj -> {
                val o = value as? JsonObject ?: return SchemaResult.Invalid(path, "expected object")
                for (k in o.keys) {
                    if (k !in schema.properties) return SchemaResult.Invalid("$path.$k", "unexpected property")
                }
                for (k in schema.required) {
                    if (k !in o) return SchemaResult.Invalid("$path.$k", "missing required property")
                }
                for ((k, v) in o) {
                    if (v is JsonNull && k !in schema.required) continue
                    val r = validate(schema.properties.getValue(k), v, "$path.$k")
                    if (r is SchemaResult.Invalid) return r
                }
                SchemaResult.Valid
            }
        }
    }
}
