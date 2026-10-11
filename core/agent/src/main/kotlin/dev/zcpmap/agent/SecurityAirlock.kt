package dev.zcpmap.agent

import dev.zcpmap.mesh.ContractOrigin
import dev.zcpmap.mesh.ContractRecord
import dev.zcpmap.mesh.ContractStatus
import dev.zcpmap.mesh.MeshPolicy
import dev.zcpmap.mesh.SessionAttestation
import dev.zcpmap.mesh.UntrustedText
import dev.zcpmap.protocol.JsonSchema
import dev.zcpmap.protocol.LifecyclePhase
import dev.zcpmap.protocol.SchemaResult
import dev.zcpmap.protocol.SchemaValidator
import dev.zcpmap.security.CapabilityAction
import dev.zcpmap.security.CapabilityManifest
import dev.zcpmap.security.CryptoEngine
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/*
 * SecurityAirlock — the deterministic, non-LLM gate between the agent and the hardware.
 *
 * Inbound (peer -> agent model):
 *   Peer data reaches the model ONLY inside tool results and observation messages, never in the system
 *   prompt. Every peer-authored string is sanitized (UntrustedText) and wrapped in an
 *   <untrusted_peer_payload> envelope with XML escaping, a random envelope id and a content hash, so
 *   a peer cannot close the envelope early or forge a second one.
 *
 * Outbound (model -> hardware):
 *   Every tool call is checked here BEFORE the router executes it:
 *     1. the tool exists and its input passes the closed JSON schema;
 *     2. no string argument smuggles URLs, absolute paths, shell metacharacter payloads, envelope
 *        tags or high-entropy blobs (exfiltration channel via negotiation text);
 *     3. rate limits (per turn and per minute);
 *     4. the referenced session is cryptographically live: handshake complete, transport keys not
 *        wiped, distance bound established, fresh UWB fix, peer manifest unexpired;
 *     5. the requested action is legal in the session's lifecycle phase and within local policy
 *        and the peer's signed manifest;
 *     6. repeated violations against one peer escalate to a cryptographic teardown of that session.
 */

data class ToolSpec(
    val name: String,
    val description: String,
    val schema: JsonSchema.Obj,
)

sealed interface AirlockDecision {
    data class Allow(val tool: String, val args: JsonObject) : AirlockDecision
    data class Deny(
        val tool: String,
        val reason: String,
        /** Non-null when the violation should tear down this peer's session. */
        val escalatedPeerId: String? = null,
    ) : AirlockDecision
}

/** Read-only view of mesh state the airlock needs; implemented over the coordinator. */
interface AirlockStateView {
    val policy: MeshPolicy
    fun knownPeer(peerId: String): Boolean
    fun attestation(peerId: String): SessionAttestation?
    fun contract(contractId: String): ContractRecord?
    fun manifest(peerId: String): CapabilityManifest?
    fun nowMillis(): Long
}

class SecurityAirlock(
    private val state: AirlockStateView,
    /** Strings that must never appear in outbound arguments (API key, ...). Re-read on every call. */
    private val secretCanaries: () -> List<String> = { emptyList() },
    private val maxCallsPerTurn: Int = 8,
    private val maxCallsPerMinute: Int = 40,
    private val violationsBeforeTeardown: Int = 3,
) {
    private val callTimes = ArrayDeque<Long>()
    private val violations = HashMap<String, ArrayDeque<Long>>()
    private var callsThisTurn = 0

    fun beginTurn() {
        callsThisTurn = 0
    }

    @Synchronized
    fun inspect(toolName: String, input: JsonElement): AirlockDecision {
        val spec = ToolCatalog.byName[toolName]
            ?: return AirlockDecision.Deny(toolName, "unknown tool '$toolName'; only the registered ZCP-MAP tools exist")
        val now = state.nowMillis()

        callsThisTurn++
        if (callsThisTurn > maxCallsPerTurn) return AirlockDecision.Deny(toolName, "per-turn tool call limit ($maxCallsPerTurn) exceeded")
        while (callTimes.isNotEmpty() && now - callTimes.first() > 60_000) callTimes.removeFirst()
        if (callTimes.size >= maxCallsPerMinute) return AirlockDecision.Deny(toolName, "rate limit: $maxCallsPerMinute tool calls per minute")
        callTimes.addLast(now)

        val args = input as? JsonObject ?: return AirlockDecision.Deny(toolName, "tool input must be a JSON object")
        when (val r = SchemaValidator.validate(spec.schema, args)) {
            is SchemaResult.Invalid -> return violation(toolName, args, "schema violation at ${r.path}: ${r.reason}")
            SchemaResult.Valid -> Unit
        }
        scanStrings(args)?.let { return violation(toolName, args, it) }

        val decision = when (toolName) {
            ToolCatalog.SCAN -> AirlockDecision.Allow(toolName, args)
            ToolCatalog.HANDSHAKE -> checkHandshake(args)
            ToolCatalog.PROPOSE -> checkPropose(args)
            ToolCatalog.EVALUATE -> checkEvaluate(args)
            ToolCatalog.RESPOND -> checkRespond(args)
            ToolCatalog.STREAM -> checkStream(args)
            ToolCatalog.TERMINATE -> checkTerminate(args)
            else -> AirlockDecision.Deny(toolName, "no policy for tool")
        }
        return if (decision is AirlockDecision.Deny) violation(toolName, args, decision.reason) else decision
    }

    private fun peerOf(args: JsonObject): String? = (args["peer_id"] as? JsonPrimitive)?.content

    private fun violation(tool: String, args: JsonObject, reason: String): AirlockDecision.Deny {
        val peer = peerOf(args) ?: (args["contract_id"] as? JsonPrimitive)?.content?.let { state.contract(it)?.peerId }
        if (peer == null || !state.knownPeer(peer)) return AirlockDecision.Deny(tool, reason)
        val now = state.nowMillis()
        val q = violations.getOrPut(peer) { ArrayDeque() }
        while (q.isNotEmpty() && now - q.first() > 5 * 60_000) q.removeFirst()
        q.addLast(now)
        val escalate = q.size >= violationsBeforeTeardown && state.attestation(peer)?.handshakeComplete == true
        if (escalate) q.clear()
        return AirlockDecision.Deny(tool, reason, if (escalate) peer else null)
    }

    // ---------------------------------------------------------------- content scanning

    private fun scanStrings(e: JsonElement, path: String = "$"): String? {
        when (e) {
            is JsonObject -> e.forEach { (k, v) -> scanStrings(v, "$path.$k")?.let { return it } }
            is JsonArray -> e.forEachIndexed { i, v -> scanStrings(v, "$path[$i]")?.let { return it } }
            is JsonPrimitive -> if (e.isString) return scanText(e.content, path)
            else -> Unit
        }
        return null
    }

    private fun scanText(s: String, path: String): String? {
        val lower = s.lowercase()
        if (lower.contains("untrusted_peer_payload")) return "$path: envelope tags may not appear in outbound arguments"
        if (URL.containsMatchIn(lower)) return "$path: URLs and network locators are forbidden"
        if (ABS_PATH.containsMatchIn(s)) return "$path: absolute or home-relative filesystem paths are forbidden"
        if (SHELL.containsMatchIn(s)) return "$path: shell metacharacter sequences are forbidden"
        if (BLOB.containsMatchIn(s)) return "$path: high-entropy blob detected (possible exfiltration)"
        for (c in secretCanaries()) {
            if (c.length >= 8 && s.contains(c.take(24))) return "$path: secret material detected in outbound argument"
        }
        if (lower.contains("sk-ant-")) return "$path: credential pattern detected"
        return null
    }

    // ---------------------------------------------------------------- per-tool policy

    private fun requireLiveSession(peer: String, needFreshFix: Boolean): String? {
        val a = state.attestation(peer) ?: return "no session with $peer"
        if (!a.handshakeComplete) return "session with $peer has not completed the Noise handshake"
        if (!a.transportKeysLive) return "session keys for $peer are wiped"
        if (a.peerFingerprint == null) return "peer identity not authenticated"
        if (!a.distanceBound && !a.codeVerified) return "no proximity proof for $peer (neither a UWB distance bound nor a confirmed code)"
        val exp = a.manifestExpiresAtSeconds ?: return "no verified capability manifest from $peer"
        if (exp * 1000 <= state.nowMillis() + 5_000) return "peer manifest expired or about to expire"
        // Code-checked sessions have no radio to re-measure; the contract evaluator makes every contract on
        // them wait for a human tap instead.
        if (needFreshFix && a.distanceBound) {
            val age = a.lastFixAgeMillis ?: return "no recent UWB fix for $peer"
            if (age > 3_000) return "UWB fix for $peer is stale (${age}ms)"
            val d = a.lastDistanceMeters ?: return "no distance"
            if (d > state.policy.maxDistanceMeters) return "peer is %.2fm away (limit %.2fm)".format(d, state.policy.maxDistanceMeters)
        }
        return null
    }

    private fun checkHandshake(args: JsonObject): AirlockDecision {
        val peer = peerOf(args)!!
        if (!state.knownPeer(peer)) return AirlockDecision.Deny(ToolCatalog.HANDSHAKE, "unknown peer $peer")
        val a = state.attestation(peer)
        if (a != null && a.phase != LifecyclePhase.TEARDOWN) return AirlockDecision.Deny(ToolCatalog.HANDSHAKE, "session already in ${a.phase}")
        return AirlockDecision.Allow(ToolCatalog.HANDSHAKE, args)
    }

    private fun checkPropose(args: JsonObject): AirlockDecision {
        val t = ToolCatalog.PROPOSE
        val peer = peerOf(args)!!
        requireLiveSession(peer, needFreshFix = true)?.let { return AirlockDecision.Deny(t, it) }
        val phase = state.attestation(peer)!!.phase
        if (phase !in setOf(LifecyclePhase.ATTESTATION_VERIFIED, LifecyclePhase.AGENT_NEGOTIATING, LifecyclePhase.SETTLEMENT_COMPLETE)) {
            return AirlockDecision.Deny(t, "cannot propose while session is $phase")
        }
        return checkTerms(t, args, peer)
    }

    private fun checkTerms(tool: String, terms: JsonObject, peer: String): AirlockDecision {
        val p = state.policy
        val bytes = terms.getValue("max_bytes").jsonPrimitive.long
        val cpu = terms.getValue("cpu_ms").jsonPrimitive.long
        if (bytes > p.maxTransferBytes) return AirlockDecision.Deny(tool, "max_bytes exceeds local policy (${p.maxTransferBytes})")
        if (cpu > p.maxCpuMillisPerContract) return AirlockDecision.Deny(tool, "cpu_ms exceeds local policy (${p.maxCpuMillisPerContract})")
        val direction = terms.getValue("direction").jsonPrimitive.content
        val m = state.manifest(peer) ?: return AirlockDecision.Deny(tool, "no peer manifest")
        val recv = m.grantFor(CapabilityAction.DATA_RECEIVE)?.maxBytes
        if (direction == "proposer_sends" && (recv ?: -1) < bytes) {
            return AirlockDecision.Deny(tool, "peer manifest grants only ${recv ?: 0} bytes for data.receive")
        }
        return AirlockDecision.Allow(tool, terms)
    }

    private fun checkEvaluate(args: JsonObject): AirlockDecision {
        val cid = args.getValue("contract_id").jsonPrimitive.content
        val c = state.contract(cid) ?: return AirlockDecision.Deny(ToolCatalog.EVALUATE, "unknown contract $cid")
        if (c.origin != ContractOrigin.REMOTE) return AirlockDecision.Deny(ToolCatalog.EVALUATE, "only incoming peer contracts are evaluated")
        return AirlockDecision.Allow(ToolCatalog.EVALUATE, args)
    }

    private fun checkRespond(args: JsonObject): AirlockDecision {
        val t = ToolCatalog.RESPOND
        val cid = args.getValue("contract_id").jsonPrimitive.content
        val c = state.contract(cid) ?: return AirlockDecision.Deny(t, "unknown contract $cid")
        if (c.origin != ContractOrigin.REMOTE) return AirlockDecision.Deny(t, "cannot respond to our own proposal")
        if (c.status != ContractStatus.PROPOSED) return AirlockDecision.Deny(t, "contract is ${c.status}")
        requireLiveSession(c.peerId, needFreshFix = true)?.let { return AirlockDecision.Deny(t, it) }
        val decision = args.getValue("decision").jsonPrimitive.content
        val counter = args["counter_terms"] as? JsonObject
        if (decision == "counter" && counter == null) return AirlockDecision.Deny(t, "decision=counter requires counter_terms")
        if (decision != "counter" && counter != null) return AirlockDecision.Deny(t, "counter_terms only allowed with decision=counter")
        if (counter != null) {
            val r = checkTerms(t, counter, c.peerId)
            if (r is AirlockDecision.Deny) return r
        }
        return AirlockDecision.Allow(t, args)
    }

    private fun checkStream(args: JsonObject): AirlockDecision {
        val t = ToolCatalog.STREAM
        val peer = peerOf(args)!!
        val cid = args.getValue("contract_id").jsonPrimitive.content
        requireLiveSession(peer, needFreshFix = true)?.let { return AirlockDecision.Deny(t, it) }
        val c = state.contract(cid) ?: return AirlockDecision.Deny(t, "unknown contract $cid")
        if (c.peerId != peer) return AirlockDecision.Deny(t, "contract $cid belongs to a different peer")
        if (c.status != ContractStatus.ACCEPTED) return AirlockDecision.Deny(t, "contract is ${c.status}, not ACCEPTED")
        if (c.localReceives) return AirlockDecision.Deny(t, "under this contract the peer sends to us")
        val a = state.attestation(peer)!!
        if (a.phase != LifecyclePhase.TASK_EXECUTING || a.executingContractId != cid) return AirlockDecision.Deny(t, "contract $cid is not the executing task")
        val path = args.getValue("source_path").jsonPrimitive.content
        if (path.split('/').any { it == ".." || it == "." || it.isEmpty() }) return AirlockDecision.Deny(t, "path traversal is forbidden")
        return AirlockDecision.Allow(t, args)
    }

    private fun checkTerminate(args: JsonObject): AirlockDecision {
        val peer = peerOf(args)!!
        if (state.attestation(peer) == null) return AirlockDecision.Deny(ToolCatalog.TERMINATE, "no session with $peer")
        return AirlockDecision.Allow(ToolCatalog.TERMINATE, args)
    }

    companion object {
        private val URL = Regex("(?:[a-z][a-z0-9+.-]{1,15}://|\\bwww\\.|\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b)")
        private val ABS_PATH = Regex("(?:^|[\\s\"'=(])(?:/(?:etc|data|sdcard|storage|proc|sys|system|dev|root|home|var|tmp)\\b|~/|[A-Za-z]:\\\\)")
        private val SHELL = Regex("(?:\\$\\(|`|;\\s*(?:rm|curl|wget|sh|bash|nc|chmod)\\b|\\|\\s*(?:sh|bash)\\b|&&\\s*\\w)")
        private val BLOB = Regex("[A-Za-z0-9+/=_-]{80,}")
    }
}

/** Builds <untrusted_peer_payload> envelopes. All peer-authored text goes through here. */
object UntrustedEnvelope {
    fun wrap(peerId: String, field: String, rawText: String, maxChars: Int = 500): String {
        val clean = UntrustedText.sanitize(rawText, maxChars)
        val id = CryptoEngine.randomBytes(6).joinToString("") { "%02x".format(it) }
        val hash = CryptoEngine.sha256(clean.toByteArray()).copyOf(8).joinToString("") { "%02x".format(it) }
        return "<untrusted_peer_payload id=\"$id\" peer=\"${xml(peerId)}\" field=\"${xml(field)}\" sha256_64=\"$hash\">" +
            xml(clean) + "</untrusted_peer_payload>"
    }

    fun xml(s: String): String {
        val sb = StringBuilder(s.length + 16)
        for (c in s) when (c) {
            '&' -> sb.append("&amp;"); '<' -> sb.append("&lt;"); '>' -> sb.append("&gt;")
            '"' -> sb.append("&quot;"); '\'' -> sb.append("&apos;")
            else -> sb.append(c)
        }
        return sb.toString()
    }
}
