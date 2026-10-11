package dev.zcpmap.agent

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI

/*
 * Model-agnostic reasoning backend. The agent kernel keeps its own transcript in the neutral
 * [ChatItem] form below and hands it to whichever backend the operator selected:
 *
 *   OnDeviceBackend          a model running on the phone itself (LiteRT-LM), fully offline
 *   OpenAiCompatibleBackend  the operator's own server on the local network
 *                            (Ollama, LM Studio, llama.cpp server, vLLM — /v1/chat/completions)
 *
 * The rule-based agent does not use a backend at all (see RuleBasedAgent).
 *
 * No backend ever receives payload bytes: only sanitized metadata and enveloped peer summaries.
 */

data class ToolCallRequest(
    val id: String,
    val name: String,
    /** Parsed arguments. A non-object value means the model produced unusable JSON; the airlock rejects it. */
    val arguments: JsonElement,
)

sealed interface ChatItem {
    data class User(val text: String) : ChatItem

    data class Assistant(
        /** Visible text with tool-call markup and reasoning removed. */
        val text: String,
        /** Exactly what the model produced; replayed verbatim to text-protocol models. */
        val raw: String,
        val toolCalls: List<ToolCallRequest>,
    ) : ChatItem

    data class ToolResult(val callId: String, val toolName: String, val content: String, val isError: Boolean) : ChatItem
}

enum class StopKind { END_TURN, TOOL_CALLS, MAX_TOKENS }

data class AssistantTurn(
    val text: String,
    val raw: String,
    val reasoning: String?,
    val toolCalls: List<ToolCallRequest>,
    val stop: StopKind,
    val inputTokens: Long = 0,
    val outputTokens: Long = 0,
)

sealed interface BackendOutcome {
    data class Success(val turn: AssistantTurn) : BackendOutcome
    /** Temporary problem (server busy, network blip, model still loading). */
    data class Retryable(val detail: String, val retryAfterMillis: Long? = null) : BackendOutcome
    /** The request itself was refused (usually too long). The kernel rebuilds a shorter transcript once. */
    data class TranscriptRejected(val detail: String) : BackendOutcome
    /** Needs operator action (no model file, wrong URL, wrong model name). */
    data class Fatal(val detail: String) : BackendOutcome
}

interface LlmBackend : AutoCloseable {
    /** Shown in the UI, e.g. "On-device · gemma3-1b-it" or "Server · qwen2.5:7b". */
    val label: String

    /** Rough upper bound for system prompt + transcript, in characters. The kernel resets before exceeding it. */
    val contextBudgetChars: Int

    /** Whether the long, detailed system prompt fits; small on-device models get the compact one. */
    val prefersCompactPrompt: Boolean

    suspend fun complete(system: String, history: List<ChatItem>, tools: List<ToolSpec>): BackendOutcome

    /** Called when the kernel discards its transcript, so stateful backends can drop theirs too. */
    fun reset() {}

    override fun close() {}
}

// ==========================================================================================
// HTTP plumbing for the operator's own server
// ==========================================================================================

data class HttpReply(val status: Int, val body: String, val retryAfterSeconds: Long?)

fun interface HttpTransport {
    suspend fun postJson(url: String, headers: Map<String, String>, body: String): HttpReply
}

/**
 * Only two kinds of endpoint are allowed, so the agent can never be pointed at a public cloud API
 * over an unencrypted link:
 *   - https:// to any host (e.g. the operator's own server with a certificate), or
 *   - http://  to a loopback, private (RFC 1918 / RFC 4193), link-local or CGNAT (Tailscale) address.
 * The http:// check runs on the resolved address at request time, so a hostname cannot sneak past it.
 */
object LocalNetworkPolicy {
    sealed interface Verdict {
        data object Allowed : Verdict
        data class Refused(val reason: String) : Verdict
    }

    fun checkUrlShape(url: String): Verdict {
        val uri = try { URI(url) } catch (e: Exception) { return Verdict.Refused("not a valid URL") }
        val scheme = uri.scheme?.lowercase() ?: return Verdict.Refused("URL needs http:// or https://")
        if (scheme != "http" && scheme != "https") return Verdict.Refused("only http:// and https:// are supported")
        if (uri.host.isNullOrBlank()) return Verdict.Refused("URL has no host")
        if (uri.userInfo != null) return Verdict.Refused("credentials in the URL are not allowed; use the token field")
        return Verdict.Allowed
    }

    fun checkResolved(url: String, resolve: (String) -> Array<InetAddress> = InetAddress::getAllByName): Verdict {
        when (val v = checkUrlShape(url)) { is Verdict.Refused -> return v; Verdict.Allowed -> Unit }
        val uri = URI(url)
        if (uri.scheme.lowercase() == "https") return Verdict.Allowed
        val addrs = try { resolve(uri.host) } catch (e: Exception) { return Verdict.Refused("cannot resolve ${uri.host}") }
        if (addrs.isEmpty()) return Verdict.Refused("cannot resolve ${uri.host}")
        val public = addrs.firstOrNull { !isLocal(it) }
        return if (public == null) Verdict.Allowed
        else Verdict.Refused("plain http:// is only allowed to addresses on your own network (${public.hostAddress} is public); use https://")
    }

    fun isLocal(a: InetAddress): Boolean {
        if (a.isLoopbackAddress || a.isLinkLocalAddress || a.isSiteLocalAddress) return true
        val b = a.address
        return when (a) {
            is Inet4Address -> (b[0].toInt() and 0xFF) == 100 && (b[1].toInt() and 0xC0) == 64 // 100.64.0.0/10
            is Inet6Address -> (b[0].toInt() and 0xFE) == 0xFC                                    // fc00::/7
            else -> false
        }
    }
}

/** Dependency-free HTTP client (HttpURLConnection) used for the operator's own server. */
class UrlConnectionTransport(
    private val connectTimeoutMillis: Int = 10_000,
    private val readTimeoutMillis: Int = 600_000,
    private val resolve: (String) -> Array<InetAddress> = InetAddress::getAllByName,
) : HttpTransport {
    override suspend fun postJson(url: String, headers: Map<String, String>, body: String): HttpReply = withContext(Dispatchers.IO) {
        when (val v = LocalNetworkPolicy.checkResolved(url, resolve)) {
            is LocalNetworkPolicy.Verdict.Refused -> throw RefusedEndpointException(v.reason)
            LocalNetworkPolicy.Verdict.Allowed -> Unit
        }
        val conn = URI(url).toURL().openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = connectTimeoutMillis
            conn.readTimeout = readTimeoutMillis
            conn.doOutput = true
            conn.instanceFollowRedirects = false
            headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(16 * 1024)
                var total = 0
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > MAX_RESPONSE_BYTES) throw IOException("response larger than $MAX_RESPONSE_BYTES bytes")
                    out.write(buf, 0, n)
                }
                out.toString(Charsets.UTF_8.name())
            } ?: ""
            HttpReply(status, text, conn.getHeaderField("retry-after")?.trim()?.toLongOrNull())
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        const val MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    }
}

class RefusedEndpointException(message: String) : IOException(message)
