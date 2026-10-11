package dev.zcpmap.agent

import dev.zcpmap.mesh.ContractStatus
import dev.zcpmap.mesh.MeshEvent
import dev.zcpmap.mesh.UntrustedText
import dev.zcpmap.protocol.LifecycleState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/*
 * Agent kernel (model-agnostic).
 *
 *   mesh events ──► observation queue ──(debounce)──► turn:
 *       user message: <state_snapshot>? + <mesh_observations> / <operator_directive>
 *       loop ≤ maxToolRounds:
 *           backend.complete(system, transcript, tools)           ← on-device model or own server
 *           tool calls → airlock → router → tool results (same order) → continue
 *           no tool calls → turn ends
 *
 * Recovery: retryable errors back off exponentially with jitter; a refused (too long) request is
 * rebuilt once from a deterministic state snapshot; operator-fixable errors fault the kernel until the
 * next operator directive. Mesh security never depends on the model: the coordinator and airlock
 * enforce every rule on their own.
 */

// ==========================================================================================
// Shared agent surface (LLM kernel and rule-based agent)
// ==========================================================================================

sealed interface KernelStatus {
    data object Stopped : KernelStatus
    data object Idle : KernelStatus
    data class Thinking(val round: Int) : KernelStatus
    data class ExecutingTool(val tool: String) : KernelStatus
    data class Backoff(val attempt: Int, val untilMillis: Long, val reason: String) : KernelStatus
    data class Faulted(val reason: String) : KernelStatus
}

enum class TranscriptKind { OBSERVATION, OPERATOR, THINKING, AGENT_TEXT, TOOL_CALL, TOOL_RESULT, AIRLOCK_DENIED, KERNEL }

data class TranscriptEntry(val kind: TranscriptKind, val text: String, val atMillis: Long, val peerId: String? = null)

data class UsageTotals(val inputTokens: Long = 0, val outputTokens: Long = 0, val requests: Long = 0)

interface AgentController {
    val label: String
    val status: StateFlow<KernelStatus>
    val transcript: StateFlow<List<TranscriptEntry>>
    val usage: StateFlow<UsageTotals>
    fun start()
    fun stop()
    /** Trusted instruction from the device owner (on-device UI). Also clears a fault. */
    fun submitOperatorDirective(text: String)
    fun clearFault()
}

/** Bounded, observable transcript shared by both agent kinds. */
class AgentLog(private val clock: () -> Long, private val capacity: Int = 500) {
    private val _entries = MutableStateFlow<List<TranscriptEntry>>(emptyList())
    val entries: StateFlow<List<TranscriptEntry>> = _entries.asStateFlow()

    @Synchronized
    fun add(kind: TranscriptKind, text: String, peerId: String? = null) {
        val list = _entries.value
        val next = if (list.size >= capacity) list.drop(list.size - capacity + 1) else list
        _entries.value = next + TranscriptEntry(kind, text, clock(), peerId)
    }
}

data class KernelConfig(
    val maxToolRoundsPerTurn: Int = 8,
    val maxHistoryItems: Int = 40,
    val observationDebounceMillis: Long = 750,
    val maxRetries: Int = 4,
)

// ==========================================================================================
// LLM kernel
// ==========================================================================================

class AgentKernel(
    private val control: MeshControl,
    private val router: ToolRouter,
    private val backend: LlmBackend,
    private val config: KernelConfig,
    private val meshEvents: Flow<MeshEvent>,
    private val scope: CoroutineScope,
    private val clock: () -> Long = System::currentTimeMillis,
    private val random: java.util.Random = java.security.SecureRandom(),
) : AgentController {
    private sealed interface Input {
        data class Observation(val json: JsonObject) : Input
        data class Operator(val text: String) : Input
    }

    private val inputs = Channel<Input>(Channel.UNLIMITED)
    private val items = ArrayList<ChatItem>()
    private var needsSnapshot = true
    private var job: Job? = null
    private val log = AgentLog(clock)
    private val tools: List<ToolSpec> = ToolCatalog.all
    private val systemPrompt: String = if (backend.prefersCompactPrompt) AgentSystemPrompt.COMPACT else AgentSystemPrompt.TEXT

    private val _status = MutableStateFlow<KernelStatus>(KernelStatus.Stopped)
    override val status: StateFlow<KernelStatus> = _status.asStateFlow()
    override val transcript: StateFlow<List<TranscriptEntry>> = log.entries
    private val _usage = MutableStateFlow(UsageTotals())
    override val usage: StateFlow<UsageTotals> = _usage.asStateFlow()
    override val label: String get() = backend.label

    override fun start() {
        if (job?.isActive == true) return
        _status.value = KernelStatus.Idle
        log.add(TranscriptKind.KERNEL, "agent online: ${backend.label}")
        job = scope.launch {
            launch { meshEvents.collect { e -> toObservation(e)?.let { inputs.trySend(Input.Observation(it)) } } }
            mainLoop()
        }
    }

    override fun stop() {
        job?.cancel()
        job = null
        _status.value = KernelStatus.Stopped
    }

    override fun submitOperatorDirective(text: String) {
        val clean = UntrustedText.sanitize(text, 1_000)
        if (clean.isEmpty()) return
        clearFault()
        inputs.trySend(Input.Operator(clean))
    }

    override fun clearFault() {
        if (_status.value is KernelStatus.Faulted) _status.value = KernelStatus.Idle
    }

    /** For tests: the transcript the next request would carry. */
    fun historySnapshot(): List<ChatItem> = items.toList()

    private suspend fun mainLoop() {
        while (scope.isActive) {
            val first = inputs.receive()
            val batch = arrayListOf(first)
            while (true) {
                val next = withTimeoutOrNull(config.observationDebounceMillis) { inputs.receive() } ?: break
                batch += next
                if (batch.size >= 32) break
            }
            if (_status.value is KernelStatus.Faulted && batch.none { it is Input.Operator }) {
                log.add(TranscriptKind.KERNEL, "agent faulted; ${batch.size} observation(s) not processed — send a directive to retry")
                continue
            }
            try {
                runTurn(batch)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log.add(TranscriptKind.KERNEL, "turn aborted: ${e.javaClass.simpleName}: ${e.message}")
                resetConversation("unexpected error")
            }
            if (_status.value !is KernelStatus.Faulted) _status.value = KernelStatus.Idle
        }
    }

    // ---------------------------------------------------------------------- turn

    private suspend fun runTurn(batch: List<Input>) {
        router.airlock.beginTurn()
        val parts = ArrayList<String>()
        val observations = batch.filterIsInstance<Input.Observation>()
        if (observations.isNotEmpty()) {
            parts += "<mesh_observations at=\"${clock() / 1000}\">\n${JsonArray(observations.map { it.json })}\n</mesh_observations>"
            observations.forEach { log.add(TranscriptKind.OBSERVATION, summarizeObservation(it.json), it.json["peer_id"]?.jsonPrimitive?.contentOrNull) }
        }
        batch.filterIsInstance<Input.Operator>().forEach {
            parts += "<operator_directive>\n${UntrustedEnvelope.xml(it.text)}\n</operator_directive>"
            log.add(TranscriptKind.OPERATOR, it.text)
        }
        val turnText = parts.joinToString("\n\n")
        if (items.size >= config.maxHistoryItems || estimateChars() + turnText.length > backend.contextBudgetChars) {
            resetConversation("context budget")
        }
        val snapshotPrefix = if (needsSnapshot) { needsSnapshot = false; "<state_snapshot>\n${stateSnapshot()}\n</state_snapshot>\n\n" } else ""
        items += ChatItem.User(snapshotPrefix + turnText)

        var round = 0
        var rebuildUsed = false
        while (round < config.maxToolRoundsPerTurn) {
            round++
            _status.value = KernelStatus.Thinking(round)
            val turn = when (val r = callWithRetry()) {
                is BackendOutcome.Success -> r.turn
                is BackendOutcome.TranscriptRejected -> {
                    if (rebuildUsed) {
                        fault("request refused twice: ${r.detail}")
                        return
                    }
                    rebuildUsed = true
                    log.add(TranscriptKind.KERNEL, "request refused (${r.detail}); rebuilding a short transcript from a state snapshot")
                    items.clear()
                    backend.reset()
                    items += ChatItem.User("<state_snapshot>\n${stateSnapshot()}\n</state_snapshot>\n\n$turnText")
                    round--
                    continue
                }
                is BackendOutcome.Fatal -> {
                    fault(r.detail)
                    return
                }
                is BackendOutcome.Retryable -> {
                    log.add(TranscriptKind.KERNEL, "giving up after ${config.maxRetries} retries: ${r.detail}")
                    resetConversation("model unavailable")
                    return
                }
            }
            _usage.value = _usage.value.let {
                it.copy(inputTokens = it.inputTokens + turn.inputTokens, outputTokens = it.outputTokens + turn.outputTokens, requests = it.requests + 1)
            }
            turn.reasoning?.takeIf { it.isNotBlank() }?.let { log.add(TranscriptKind.THINKING, it.take(600)) }
            if (turn.text.isNotBlank()) log.add(TranscriptKind.AGENT_TEXT, turn.text.take(800))
            items += ChatItem.Assistant(turn.text, turn.raw, turn.toolCalls)

            if (turn.toolCalls.isEmpty()) {
                if (turn.stop == StopKind.MAX_TOKENS) log.add(TranscriptKind.KERNEL, "reply cut off at the output token limit")
                return
            }
            items += executeTools(turn.toolCalls)
        }
        log.add(TranscriptKind.KERNEL, "tool round limit (${config.maxToolRoundsPerTurn}) reached; waiting for new input")
    }

    private suspend fun executeTools(calls: List<ToolCallRequest>): List<ChatItem.ToolResult> {
        val results = ArrayList<ChatItem.ToolResult>(calls.size)
        for (c in calls) {
            _status.value = KernelStatus.ExecutingTool(c.name)
            log.add(TranscriptKind.TOOL_CALL, "${c.name} ${compact(c.arguments)}", (c.arguments as? JsonObject)?.get("peer_id")?.jsonPrimitive?.contentOrNull)
            val r = router.call(c.name, c.arguments)
            if (r.airlockDenied) {
                log.add(TranscriptKind.AIRLOCK_DENIED, "${c.name}: ${r.content["reason"]?.jsonPrimitive?.content}" +
                    (r.escalatedPeerId?.let { " — session with $it torn down" } ?: ""))
            } else {
                log.add(TranscriptKind.TOOL_RESULT, "${c.name} → ${if (r.isError) "error: " + (r.content["reason"]?.jsonPrimitive?.contentOrNull ?: "") else "ok"}")
            }
            results += ChatItem.ToolResult(c.id, c.name, r.content.toString(), r.isError)
        }
        return results
    }

    private suspend fun callWithRetry(): BackendOutcome {
        var attempt = 0
        while (true) {
            val outcome = backend.complete(systemPrompt, items.toList(), tools)
            if (outcome !is BackendOutcome.Retryable || attempt >= config.maxRetries) return outcome
            attempt++
            val backoff = outcome.retryAfterMillis ?: (minOf(30_000L, 1_000L shl attempt) + random.nextInt(750))
            _status.value = KernelStatus.Backoff(attempt, clock() + backoff, outcome.detail)
            log.add(TranscriptKind.KERNEL, "retry $attempt/${config.maxRetries} in ${backoff}ms (${outcome.detail})")
            delay(backoff)
        }
    }

    // ---------------------------------------------------------------------- helpers

    private val toolsChars: Int = TextToolProtocol.instructions(tools, compact = backend.prefersCompactPrompt).length

    private fun estimateChars(): Int = systemPrompt.length + toolsChars + items.sumOf {
        when (it) {
            is ChatItem.User -> it.text.length
            is ChatItem.Assistant -> it.raw.length + it.toolCalls.sumOf { c -> c.arguments.toString().length + 40 }
            is ChatItem.ToolResult -> it.content.length + 60
        }
    }

    private fun resetConversation(why: String) {
        items.clear()
        backend.reset()
        needsSnapshot = true
        log.add(TranscriptKind.KERNEL, "conversation reset ($why); next turn starts from a state snapshot")
    }

    private fun fault(reason: String) {
        _status.value = KernelStatus.Faulted(reason)
        log.add(TranscriptKind.KERNEL, "FAULT: $reason")
        resetConversation("fault")
    }

    /** Deterministic, non-LLM summary of mesh state; peer strings only inside envelopes. */
    private fun stateSnapshot(): String = buildJsonObject {
        put("local_fingerprint", control.localFingerprint)
        put("radius_m", control.policy.maxDistanceMeters)
        put("outbox", buildJsonArray {
            control.outboxFiles().take(20).forEach { f -> add(buildJsonObject { put("path", f.path); put("bytes", f.bytes) }) }
        })
        put("peers", buildJsonArray {
            control.peerIds().forEach { pid ->
                val snap = control.snapshot(pid) ?: return@forEach
                add(buildJsonObject {
                    put("peer_id", pid)
                    put("phase", snap.state.phase.name)
                    snap.peerFingerprint?.let { put("fingerprint", it) }
                    snap.boundDistanceMeters?.let { put("bound_distance_m", Math.round(it * 100) / 100.0) }
                    put("open_contracts", buildJsonArray {
                        snap.openContracts.forEach { cid ->
                            val c = control.contract(cid) ?: return@forEach
                            add(buildJsonObject {
                                put("contract_id", cid); put("origin", c.origin.name); put("status", c.status.name)
                                put("task_type", c.terms.taskType.wire); put("direction", c.terms.direction.wire); put("max_bytes", c.terms.maxBytes)
                            })
                        }
                    })
                })
            }
        })
    }.toString()

    private fun toObservation(e: MeshEvent): JsonObject? = when (e) {
        is MeshEvent.PeerDiscovered -> buildJsonObject { put("type", "peer_discovered"); put("peer_id", e.peerId); put("verified", false) }
        is MeshEvent.PeerLost -> buildJsonObject { put("type", "peer_lost"); put("peer_id", e.peerId) }
        is MeshEvent.StateChanged -> when (val s = e.state) {
            is LifecycleState.AttestationVerified -> buildJsonObject {
                put("type", "peer_attested"); put("peer_id", e.peerId); put("fingerprint", s.peerFingerprint)
                put("bound_distance_m", Math.round(s.boundDistanceMeters * 100) / 100.0)
                put("proximity", if (s.boundDistanceMeters < 0) "code_check" else "uwb")
            }
            is LifecycleState.Teardown -> buildJsonObject {
                put("type", "session_ended"); put("peer_id", e.peerId); put("reason", s.reason.name); put("from_phase", s.fromPhase.name)
            }
            else -> null
        }
        is MeshEvent.ContractProposed -> buildJsonObject {
            put("type", "contract_proposed"); put("peer_id", e.peerId); put("contract_id", e.contract.contractId)
            put("task_type", e.contract.terms.taskType.wire); put("direction", e.contract.terms.direction.wire)
            put("max_bytes", e.contract.terms.maxBytes); put("cpu_ms", e.contract.terms.cpuMillis)
            put("duration_s", e.contract.terms.durationSeconds); put("credits", e.contract.terms.credits)
            put("expires_at", e.contract.expiresAtSeconds)
            e.contract.counterOf?.let { put("counter_of", it) }
            put("summary", UntrustedEnvelope.wrap(e.peerId, "contract.summary", e.contract.terms.summary))
        }
        is MeshEvent.ContractAnswered -> buildJsonObject {
            put("type", "contract_answered"); put("peer_id", e.peerId); put("contract_id", e.contractId)
            put("decision", e.decision.wire); e.reason?.let { put("reason_code", it) }
            put("status", control.contract(e.contractId)?.status?.name ?: ContractStatus.FAILED.name)
        }
        is MeshEvent.TransferCompleted -> buildJsonObject {
            put("type", "transfer_completed"); put("peer_id", e.peerId); put("contract_id", e.contractId)
            put("inbound", e.inbound); put("path", e.path); put("merkle_root", e.merkleRootHex)
        }
        is MeshEvent.SettlementCompleted -> buildJsonObject {
            put("type", "settlement_completed"); put("peer_id", e.peerId); put("contract_id", e.contractId); put("receipt_hash", e.receiptHashHex)
        }
        is MeshEvent.SecurityAlert -> buildJsonObject {
            put("type", "security_alert"); put("peer_id", e.peerId); put("reason", e.reason.name)
        }
        is MeshEvent.ApprovalRequired -> buildJsonObject {
            put("type", "awaiting_user_approval"); put("peer_id", e.peerId); put("approval_id", e.approvalId)
        }
        is MeshEvent.CodeCheckRequired -> buildJsonObject {
            put("type", "awaiting_code_check"); put("peer_id", e.peerId)
            put("note", "the people holding both phones must compare a code and confirm on each screen; tools for this peer will wait")
        }
        is MeshEvent.Ranging, is MeshEvent.TransferProgress, is MeshEvent.Log -> null
    }

    private fun summarizeObservation(o: JsonObject): String {
        val type = o["type"]?.jsonPrimitive?.content ?: "?"
        val extras = listOf("contract_id", "reason", "decision", "bound_distance_m").mapNotNull { k -> o[k]?.jsonPrimitive?.contentOrNull?.let { "$k=$it" } }
        return (listOf(type) + extras).joinToString(" ")
    }

    private fun compact(e: JsonElement): String = e.toString().let { if (it.length > 220) it.take(217) + "..." else it }
}
