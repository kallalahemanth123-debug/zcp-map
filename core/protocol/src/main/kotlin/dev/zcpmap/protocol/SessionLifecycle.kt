package dev.zcpmap.protocol

/*
 * Deterministic P2P lifecycle FSM:
 *
 *   IDLE -> UWB_RANGING -> NOISE_HANDSHAKE -> ATTESTATION_VERIFIED -> AGENT_NEGOTIATING
 *        -> TASK_EXECUTING -> SETTLEMENT_COMPLETE -> TEARDOWN
 *
 * Semantics of each state (the ordering constraint is cryptographic, see below):
 *
 *  UWB_RANGING         Proximity acquisition: the peer was discovered over BLE/Nearby with a
 *                      rotating beacon token, a link exists, and the peer's UWB capability is
 *                      being probed. No ranging result is trusted yet.
 *  NOISE_HANDSHAKE     Noise_XX handshake, then (sub-phase DISTANCE_BOUNDING) secure UWB ranging
 *                      whose STS key is derived from the handshake's secret exporter, then
 *                      (sub-phase MANIFEST_EXCHANGE) signed capability manifests. Secure ranging
 *                      cannot precede the handshake: the STS key must be a fresh shared secret
 *                      that only the two authenticated endpoints hold, otherwise a relay could
 *                      simply forward the scrambled timestamp sequence.
 *  ATTESTATION_VERIFIED Handshake + distance bound + manifest all verified.
 *  AGENT_NEGOTIATING   Contracts are being proposed/evaluated.
 *  TASK_EXECUTING      A contract is accepted; capability token issued; payloads may flow.
 *  SETTLEMENT_COMPLETE Signed settlement receipts exchanged. May loop back to negotiating.
 *  TEARDOWN            Absorbing. Keys are zeroized by the owner of the state machine.
 *
 * Every (state, event) pair not listed in [SessionLifecycle.transition] is a protocol violation
 * and drives the machine to TEARDOWN (fail closed).
 */

enum class LifecyclePhase {
    IDLE, UWB_RANGING, NOISE_HANDSHAKE, ATTESTATION_VERIFIED, AGENT_NEGOTIATING,
    TASK_EXECUTING, SETTLEMENT_COMPLETE, TEARDOWN
}

enum class HandshakeRole { INITIATOR, RESPONDER }

enum class HandshakeSubPhase { NOISE_EXCHANGE, DISTANCE_BOUNDING, MANIFEST_EXCHANGE }

enum class TeardownReason {
    LOCAL_REQUEST,
    PEER_ABORT,
    AUTHENTICATION_FAILED,
    REPLAY_DETECTED,
    DISTANCE_BOUND_EXCEEDED,
    RANGING_LOST,
    ATTESTATION_INVALID,
    POLICY_VIOLATION,
    PROTOCOL_VIOLATION,
    TIMEOUT,
    LINK_LOST,
    AGENT_SCHEMA_VIOLATION,
}

sealed interface LifecycleState {
    val phase: LifecyclePhase

    data object Idle : LifecycleState {
        override val phase = LifecyclePhase.IDLE
    }

    data class UwbRanging(val endpointId: String, val enteredAtMillis: Long) : LifecycleState {
        override val phase = LifecyclePhase.UWB_RANGING
    }

    data class NoiseHandshake(
        val role: HandshakeRole,
        val subPhase: HandshakeSubPhase,
        val enteredAtMillis: Long,
        /** Set when DISTANCE_BOUNDING succeeds; carried into ATTESTATION_VERIFIED. */
        val boundDistanceMeters: Double? = null,
    ) : LifecycleState {
        override val phase = LifecyclePhase.NOISE_HANDSHAKE
    }

    data class AttestationVerified(
        val peerFingerprint: String,
        val boundDistanceMeters: Double,
        val enteredAtMillis: Long,
    ) : LifecycleState {
        override val phase = LifecyclePhase.ATTESTATION_VERIFIED
    }

    data class AgentNegotiating(
        val peerFingerprint: String,
        val openContractIds: Set<String>,
        val enteredAtMillis: Long,
    ) : LifecycleState {
        override val phase = LifecyclePhase.AGENT_NEGOTIATING
    }

    data class TaskExecuting(
        val peerFingerprint: String,
        val contractId: String,
        val enteredAtMillis: Long,
    ) : LifecycleState {
        override val phase = LifecyclePhase.TASK_EXECUTING
    }

    data class SettlementComplete(
        val peerFingerprint: String,
        val contractId: String,
        val receiptHashHex: String,
        val enteredAtMillis: Long,
    ) : LifecycleState {
        override val phase = LifecyclePhase.SETTLEMENT_COMPLETE
    }

    data class Teardown(
        val reason: TeardownReason,
        val fromPhase: LifecyclePhase,
        val detail: String,
    ) : LifecycleState {
        override val phase = LifecyclePhase.TEARDOWN
    }
}

sealed interface LifecycleEvent {
    data class PeerDiscovered(val endpointId: String) : LifecycleEvent
    data class LinkEstablished(val role: HandshakeRole) : LifecycleEvent
    data object NoiseCompleted : LifecycleEvent
    data class DistanceBoundVerified(val distanceMeters: Double) : LifecycleEvent
    data class ManifestVerified(val peerFingerprint: String) : LifecycleEvent
    data class ContractOpened(val contractId: String) : LifecycleEvent
    data class ContractDeclined(val contractId: String) : LifecycleEvent
    data class ContractAccepted(val contractId: String) : LifecycleEvent
    data class SettlementSigned(val contractId: String, val receiptHashHex: String) : LifecycleEvent
    data object ResumeNegotiation : LifecycleEvent
    data class SecurityViolation(val reason: TeardownReason, val detail: String) : LifecycleEvent
    data class Terminate(val reason: TeardownReason, val detail: String) : LifecycleEvent
}

sealed interface Transition {
    val next: LifecycleState

    data class Moved(override val next: LifecycleState) : Transition
    data class Stayed(override val next: LifecycleState) : Transition
    data class Violation(override val next: LifecycleState.Teardown, val event: LifecycleEvent) : Transition
}

object SessionLifecycle {
    /** Wall-clock budget per state; exceeding it is a TIMEOUT teardown. 0 = unbounded. */
    fun deadlineMillis(state: LifecycleState): Long = when (state) {
        LifecycleState.Idle -> 0
        is LifecycleState.UwbRanging -> 15_000
        is LifecycleState.NoiseHandshake -> when (state.subPhase) {
            HandshakeSubPhase.NOISE_EXCHANGE -> 10_000
            HandshakeSubPhase.DISTANCE_BOUNDING -> 12_000
            HandshakeSubPhase.MANIFEST_EXCHANGE -> 8_000
        }
        is LifecycleState.AttestationVerified -> 120_000
        is LifecycleState.AgentNegotiating -> 300_000
        is LifecycleState.TaskExecuting -> 1_800_000
        is LifecycleState.SettlementComplete -> 300_000
        is LifecycleState.Teardown -> 0
    }

    fun isExpired(state: LifecycleState, nowMillis: Long): Boolean {
        val budget = deadlineMillis(state)
        if (budget == 0L) return false
        val entered = when (state) {
            is LifecycleState.UwbRanging -> state.enteredAtMillis
            is LifecycleState.NoiseHandshake -> state.enteredAtMillis
            is LifecycleState.AttestationVerified -> state.enteredAtMillis
            is LifecycleState.AgentNegotiating -> state.enteredAtMillis
            is LifecycleState.TaskExecuting -> state.enteredAtMillis
            is LifecycleState.SettlementComplete -> state.enteredAtMillis
            else -> return false
        }
        return nowMillis - entered > budget
    }

    fun transition(state: LifecycleState, event: LifecycleEvent, nowMillis: Long): Transition {
        // Universal edges: violations and explicit termination reach TEARDOWN from anywhere.
        when (event) {
            is LifecycleEvent.SecurityViolation ->
                return Transition.Moved(LifecycleState.Teardown(event.reason, state.phase, event.detail))
            is LifecycleEvent.Terminate ->
                return if (state is LifecycleState.Teardown) Transition.Stayed(state)
                else Transition.Moved(LifecycleState.Teardown(event.reason, state.phase, event.detail))
            else -> Unit
        }
        if (state is LifecycleState.Teardown) return Transition.Stayed(state)

        val next: LifecycleState? = when (state) {
            LifecycleState.Idle -> when (event) {
                is LifecycleEvent.PeerDiscovered -> LifecycleState.UwbRanging(event.endpointId, nowMillis)
                else -> null
            }
            is LifecycleState.UwbRanging -> when (event) {
                is LifecycleEvent.LinkEstablished ->
                    LifecycleState.NoiseHandshake(event.role, HandshakeSubPhase.NOISE_EXCHANGE, nowMillis)
                else -> null
            }
            is LifecycleState.NoiseHandshake -> when {
                event is LifecycleEvent.NoiseCompleted && state.subPhase == HandshakeSubPhase.NOISE_EXCHANGE ->
                    state.copy(subPhase = HandshakeSubPhase.DISTANCE_BOUNDING, enteredAtMillis = nowMillis)
                event is LifecycleEvent.DistanceBoundVerified && state.subPhase == HandshakeSubPhase.DISTANCE_BOUNDING ->
                    state.copy(
                        subPhase = HandshakeSubPhase.MANIFEST_EXCHANGE,
                        enteredAtMillis = nowMillis,
                        boundDistanceMeters = event.distanceMeters,
                    )
                event is LifecycleEvent.ManifestVerified && state.subPhase == HandshakeSubPhase.MANIFEST_EXCHANGE &&
                    state.boundDistanceMeters != null ->
                    LifecycleState.AttestationVerified(event.peerFingerprint, state.boundDistanceMeters, nowMillis)
                else -> null
            }
            is LifecycleState.AttestationVerified -> when (event) {
                is LifecycleEvent.ContractOpened ->
                    LifecycleState.AgentNegotiating(state.peerFingerprint, setOf(event.contractId), nowMillis)
                else -> null
            }
            is LifecycleState.AgentNegotiating -> when (event) {
                is LifecycleEvent.ContractOpened ->
                    if (state.openContractIds.size >= MAX_OPEN_CONTRACTS) null
                    else state.copy(openContractIds = state.openContractIds + event.contractId)
                is LifecycleEvent.ContractDeclined ->
                    if (event.contractId !in state.openContractIds) null
                    else state.copy(openContractIds = state.openContractIds - event.contractId)
                is LifecycleEvent.ContractAccepted ->
                    if (event.contractId !in state.openContractIds) null
                    else LifecycleState.TaskExecuting(state.peerFingerprint, event.contractId, nowMillis)
                else -> null
            }
            is LifecycleState.TaskExecuting -> when (event) {
                is LifecycleEvent.SettlementSigned ->
                    if (event.contractId != state.contractId) null
                    else LifecycleState.SettlementComplete(state.peerFingerprint, state.contractId, event.receiptHashHex, nowMillis)
                else -> null
            }
            is LifecycleState.SettlementComplete -> when (event) {
                LifecycleEvent.ResumeNegotiation ->
                    LifecycleState.AgentNegotiating(state.peerFingerprint, emptySet(), nowMillis)
                is LifecycleEvent.ContractOpened ->
                    LifecycleState.AgentNegotiating(state.peerFingerprint, setOf(event.contractId), nowMillis)
                else -> null
            }
            is LifecycleState.Teardown -> state
        }

        return if (next == null) {
            Transition.Violation(
                LifecycleState.Teardown(TeardownReason.PROTOCOL_VIOLATION, state.phase, "illegal event ${event::class.simpleName} in ${state.phase}"),
                event,
            )
        } else if (next == state) {
            Transition.Stayed(next)
        } else {
            Transition.Moved(next)
        }
    }

    const val MAX_OPEN_CONTRACTS = 4
}
