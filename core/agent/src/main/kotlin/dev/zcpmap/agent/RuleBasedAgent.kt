package dev.zcpmap.agent

import dev.zcpmap.mesh.ContractDecision
import dev.zcpmap.mesh.MeshEvent
import dev.zcpmap.mesh.TaskType
import dev.zcpmap.mesh.TransferDirection
import dev.zcpmap.mesh.UntrustedText
import dev.zcpmap.protocol.LifecyclePhase
import dev.zcpmap.protocol.LifecycleState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.concurrent.ConcurrentHashMap

/*
 * Deterministic agent: no language model, fully offline, every decision reproducible.
 *
 * Incoming contracts are decided by [RulePolicy] (after the same deterministic feasibility check the
 * LLM agents use). Outgoing work is driven by short typed commands in the directive bar:
 *
 *   share <file> [peer]   handshake if needed → propose file_share → stream when accepted → settle → wipe
 *   connect <peer>        run the secure handshake only
 *   scan                  list peers and their verification state
 *   wipe <peer|all>       end sessions and zeroize keys
 *   auto on|off           accept/reject incoming contracts automatically
 *   files                 list files in the outbox
 *   help
 *
 * Every action still goes through the ToolRouter, so the airlock enforces exactly the same rules as
 * it does for model-driven agents.
 */
data class RulePolicy(
    val autoAccept: Boolean = true,
    /** Largest incoming transfer accepted without asking (bigger ones are rejected). */
    val maxAcceptBytes: Long = 64L * 1024 * 1024,
    val allowedTaskTypes: Set<TaskType> = setOf(TaskType.FILE_SHARE, TaskType.DATA_EXCHANGE),
    /** End the session automatically after a file we sent has been settled. */
    val wipeAfterSettlement: Boolean = true,
)

class RuleBasedAgent(
    private val control: MeshControl,
    private val router: ToolRouter,
    initialPolicy: RulePolicy,
    private val meshEvents: Flow<MeshEvent>,
    private val scope: CoroutineScope,
    clock: () -> Long = System::currentTimeMillis,
) : AgentController {
    private sealed interface Input {
        data class Event(val e: MeshEvent) : Input
        data class Command(val text: String) : Input
    }

    private data class PendingShare(val peerId: String, val path: String)

    private val inputs = Channel<Input>(Channel.UNLIMITED)
    private val log = AgentLog(clock)
    private val pendingShares = ConcurrentHashMap<String, PendingShare>()
    private val sentContracts = ConcurrentHashMap.newKeySet<String>()
    @Volatile private var policy = initialPolicy
    private var job: Job? = null

    private val _status = MutableStateFlow<KernelStatus>(KernelStatus.Stopped)
    override val status: StateFlow<KernelStatus> = _status.asStateFlow()
    override val transcript: StateFlow<List<TranscriptEntry>> = log.entries
    override val usage: StateFlow<UsageTotals> = MutableStateFlow(UsageTotals()).asStateFlow()
    override val label: String get() = "Rule-based (no model)"

    val currentPolicy: RulePolicy get() = policy

    override fun start() {
        if (job?.isActive == true) return
        _status.value = KernelStatus.Idle
        log.add(TranscriptKind.KERNEL, "rule-based agent online — auto-accept ${if (policy.autoAccept) "ON" else "OFF"}; type 'help' for commands")
        job = scope.launch {
            launch { meshEvents.collect { inputs.trySend(Input.Event(it)) } }
            for (input in inputs) {
                try {
                    when (input) {
                        is Input.Event -> onEvent(input.e)
                        is Input.Command -> onCommand(input.text)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    log.add(TranscriptKind.KERNEL, "error: ${e.javaClass.simpleName}: ${e.message}")
                }
                _status.value = KernelStatus.Idle
            }
        }
    }

    override fun stop() {
        job?.cancel()
        job = null
        _status.value = KernelStatus.Stopped
    }

    override fun submitOperatorDirective(text: String) {
        val clean = UntrustedText.sanitize(text, 300)
        if (clean.isNotEmpty()) inputs.trySend(Input.Command(clean))
    }

    override fun clearFault() = Unit

    // ------------------------------------------------------------------ events

    private suspend fun onEvent(e: MeshEvent) {
        when (e) {
            is MeshEvent.ContractProposed -> {
                val c = e.contract
                log.add(TranscriptKind.OBSERVATION, "incoming ${c.terms.taskType.wire} ${c.terms.direction.wire} ${c.terms.maxBytes} B (${c.contractId})", e.peerId)
                if (!policy.autoAccept) {
                    log.add(TranscriptKind.AGENT_TEXT, "auto-accept is OFF; leaving ${c.contractId} unanswered (it will expire)")
                    return
                }
                val eval = call(ToolCatalog.EVALUATE, buildJsonObject { put("contract_id", c.contractId) }) ?: return
                val verdict = eval["verdict"]?.jsonPrimitive?.contentOrNull
                val reason = when {
                    c.terms.taskType !in policy.allowedTaskTypes -> "policy"
                    c.terms.direction == TransferDirection.ACCEPTOR_SENDS -> "scope" // we never pick files to send on a peer's request
                    c.terms.maxBytes > policy.maxAcceptBytes -> "policy"
                    verdict == "INFEASIBLE" -> "insufficient_resources"
                    else -> null
                }
                val decision = if (reason == null) "accept" else "reject"
                call(ToolCatalog.RESPOND, buildJsonObject {
                    put("contract_id", c.contractId); put("decision", decision); put("reason", reason ?: "ok")
                })
                log.add(TranscriptKind.AGENT_TEXT, "${decision}ed ${c.contractId}${reason?.let { " ($it)" } ?: ""}", e.peerId)
            }
            is MeshEvent.ContractAnswered -> {
                val share = pendingShares[e.contractId] ?: return
                if (e.decision != ContractDecision.ACCEPT) {
                    pendingShares.remove(e.contractId)
                    log.add(TranscriptKind.AGENT_TEXT, "peer declined ${e.contractId} (${e.reason}); ending session", e.peerId)
                    call(ToolCatalog.TERMINATE, buildJsonObject { put("peer_id", share.peerId); put("reason", "task_complete") })
                    return
                }
                pendingShares.remove(e.contractId)
                sentContracts += e.contractId
                log.add(TranscriptKind.AGENT_TEXT, "peer accepted; streaming ${share.path}", e.peerId)
                // Streaming can take minutes; run it outside the event loop.
                scope.launch {
                    val r = call(ToolCatalog.STREAM, buildJsonObject {
                        put("peer_id", share.peerId); put("contract_id", e.contractId); put("source_path", share.path)
                    })
                    if (r != null) log.add(TranscriptKind.AGENT_TEXT, "sent ${r["bytes"]?.jsonPrimitive?.content} B; settled=${r["settled"]?.jsonPrimitive?.content}", share.peerId)
                }
            }
            is MeshEvent.SettlementCompleted -> {
                log.add(TranscriptKind.OBSERVATION, "settlement signed for ${e.contractId}", e.peerId)
                if (e.contractId in sentContracts && policy.wipeAfterSettlement) {
                    sentContracts.remove(e.contractId)
                    call(ToolCatalog.TERMINATE, buildJsonObject { put("peer_id", e.peerId); put("reason", "task_complete") })
                }
            }
            is MeshEvent.TransferCompleted -> if (e.inbound) log.add(TranscriptKind.OBSERVATION, "received file → ${e.path}", e.peerId)
            is MeshEvent.ApprovalRequired -> log.add(TranscriptKind.OBSERVATION, "waiting for your APPROVE/DENY tap (${e.approvalId})", e.peerId)
            is MeshEvent.CodeCheckRequired -> log.add(TranscriptKind.OBSERVATION, "check that both phones show ${e.code}, then tap CODES MATCH on both", e.peerId)
            is MeshEvent.SecurityAlert -> log.add(TranscriptKind.OBSERVATION, "security alert: ${e.reason}", e.peerId)
            is MeshEvent.StateChanged -> if (e.state is LifecycleState.AttestationVerified) {
                val d = (e.state as LifecycleState.AttestationVerified).boundDistanceMeters
                log.add(TranscriptKind.OBSERVATION, if (d < 0) "peer verified by code" else "peer verified at %.2f m".format(d), e.peerId)
            }
            else -> Unit
        }
    }

    // ------------------------------------------------------------------ commands

    private suspend fun onCommand(text: String) {
        log.add(TranscriptKind.OPERATOR, text)
        router.airlock.beginTurn()
        val parts = text.trim().split(Regex("\\s+"))
        when (parts[0].lowercase()) {
            "help", "?" -> log.add(TranscriptKind.AGENT_TEXT, "commands: share <file> [peer] · connect <peer> · scan · files · wipe <peer|all> · auto on|off")
            "scan" -> scanAndReport()
            "files" -> {
                val files = control.outboxFiles()
                log.add(TranscriptKind.AGENT_TEXT, if (files.isEmpty()) "outbox is empty" else files.joinToString(" · ") { "${it.path} (${it.bytes} B)" })
            }
            "auto" -> {
                val on = parts.getOrNull(1)?.lowercase()
                if (on != "on" && on != "off") return log.add(TranscriptKind.AGENT_TEXT, "usage: auto on|off")
                policy = policy.copy(autoAccept = on == "on")
                log.add(TranscriptKind.AGENT_TEXT, "auto-accept ${on.uppercase()}")
            }
            "connect" -> {
                val peer = resolvePeer(parts.getOrNull(1)) ?: return
                connect(peer)
            }
            "wipe" -> {
                val arg = parts.getOrNull(1) ?: return log.add(TranscriptKind.AGENT_TEXT, "usage: wipe <peer|all>")
                val targets = if (arg == "all") control.peerIds().filter { control.attestation(it) != null } else listOfNotNull(resolvePeer(arg))
                targets.forEach { call(ToolCatalog.TERMINATE, buildJsonObject { put("peer_id", it); put("reason", "user_request") }) }
                if (targets.isEmpty()) log.add(TranscriptKind.AGENT_TEXT, "no sessions to wipe")
            }
            "share", "send" -> {
                val rawPath = parts.getOrNull(1) ?: return log.add(TranscriptKind.AGENT_TEXT, "usage: share <file> [peer]")
                val path = if (rawPath.startsWith("outbox/")) rawPath else "outbox/$rawPath"
                val file = control.outboxFiles().firstOrNull { it.path == path }
                    ?: return log.add(TranscriptKind.AGENT_TEXT, "$path is not in the outbox (type 'files')")
                val peer = resolvePeer(parts.getOrNull(2)) ?: return
                if (!connect(peer)) return
                val r = call(ToolCatalog.PROPOSE, buildJsonObject {
                    put("peer_id", peer); put("task_type", TaskType.FILE_SHARE.wire); put("direction", TransferDirection.PROPOSER_SENDS.wire)
                    put("max_bytes", file.bytes); put("cpu_ms", 0); put("duration_s", 600); put("credits", 0)
                    put("summary", "Share one file from the operator")
                }) ?: return
                val cid = r["contract_id"]?.jsonPrimitive?.contentOrNull ?: return
                pendingShares[cid] = PendingShare(peer, path)
                log.add(TranscriptKind.AGENT_TEXT, "proposed $cid (${file.bytes} B); waiting for the peer to accept", peer)
            }
            else -> log.add(TranscriptKind.AGENT_TEXT, "unknown command '${parts[0]}' — type 'help'")
        }
    }

    private suspend fun connect(peer: String): Boolean {
        val phase = control.attestation(peer)?.phase
        if (phase != null && phase != LifecyclePhase.TEARDOWN) {
            if (phase.ordinal >= LifecyclePhase.ATTESTATION_VERIFIED.ordinal) return true
            log.add(TranscriptKind.AGENT_TEXT, "session with $peer is still in $phase; try again shortly", peer)
            return false
        }
        log.add(TranscriptKind.AGENT_TEXT, "connecting: identity check, then distance check…", peer)
        return call(ToolCatalog.HANDSHAKE, buildJsonObject { put("peer_id", peer) }) != null
    }

    /** Explicit id (full or last 4+ hex chars), or the only/closest peer when omitted. */
    private fun resolvePeer(arg: String?): String? {
        val ids = control.peerIds()
        if (ids.isEmpty()) { log.add(TranscriptKind.AGENT_TEXT, "no peers in range"); return null }
        if (arg != null) {
            val match = ids.filter { it == arg || (arg.length >= 4 && it.endsWith(arg)) }
            if (match.size == 1) return match[0]
            log.add(TranscriptKind.AGENT_TEXT, if (match.isEmpty()) "no peer matches '$arg'" else "'$arg' matches several peers; use more characters")
            return null
        }
        val verified = ids.filter { (control.attestation(it)?.phase?.ordinal ?: -1) >= LifecyclePhase.ATTESTATION_VERIFIED.ordinal && control.attestation(it)?.phase != LifecyclePhase.TEARDOWN }
        val pool = verified.ifEmpty { ids }
        if (pool.size == 1) return pool[0]
        val nearest = pool.minByOrNull { control.attestation(it)?.lastDistanceMeters ?: Double.MAX_VALUE }
        if (nearest != null && control.attestation(nearest)?.lastDistanceMeters != null) return nearest
        log.add(TranscriptKind.AGENT_TEXT, "${pool.size} peers in range; name one: ${pool.joinToString { it.takeLast(4) }}")
        return null
    }

    private suspend fun scanAndReport() {
        val r = call(ToolCatalog.SCAN, buildJsonObject { put("include_unverified", true) }) ?: return
        val peers = (r["peers"] as? JsonArray).orEmptyList()
        if (peers.isEmpty()) return log.add(TranscriptKind.AGENT_TEXT, "no peers in range")
        peers.forEach { p ->
            val o = p.jsonObject
            val id = o["peer_id"]?.jsonPrimitive?.content ?: "?"
            val d = o["distance_m"]?.jsonPrimitive?.contentOrNull?.let { " at $it m" } ?: ""
            val phase = o["phase"]?.jsonPrimitive?.content
            val text = when {
                o["verified"]?.jsonPrimitive?.content == "true" -> "connected and verified$d"
                phase == LifecyclePhase.IDLE.name -> "found nearby, not connected yet (tap CONNECT or type: connect ${id.takeLast(4)})"
                phase == LifecyclePhase.TEARDOWN.name -> "last connection ended; you can connect again in a few seconds"
                else -> "connecting… ($phase)"
            }
            log.add(TranscriptKind.AGENT_TEXT, "${id.takeLast(4)}: $text", id)
        }
    }

    /** Executes through the airlock. Returns the result object, or null after logging the failure. */
    private suspend fun call(tool: String, args: JsonObject): JsonObject? {
        _status.value = KernelStatus.ExecutingTool(tool)
        log.add(TranscriptKind.TOOL_CALL, "$tool $args", args["peer_id"]?.jsonPrimitive?.contentOrNull)
        val r = router.call(tool, args)
        return if (r.isError) {
            log.add(if (r.airlockDenied) TranscriptKind.AIRLOCK_DENIED else TranscriptKind.TOOL_RESULT,
                "$tool: ${r.content["reason"]?.jsonPrimitive?.contentOrNull ?: r.content}")
            null
        } else {
            log.add(TranscriptKind.TOOL_RESULT, "$tool → ok")
            r.content
        }
    }

    private fun JsonArray?.orEmptyList() = this ?: JsonArray(emptyList())
}
