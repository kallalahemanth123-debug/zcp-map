package dev.zcpmap.mesh

import dev.zcpmap.protocol.AbortCode
import dev.zcpmap.protocol.AckBody
import dev.zcpmap.protocol.ChunkBody
import dev.zcpmap.protocol.DecodeResult
import dev.zcpmap.protocol.FrameHeader
import dev.zcpmap.protocol.FrameSequenceValidator
import dev.zcpmap.protocol.FrameType
import dev.zcpmap.protocol.HandshakeRole
import dev.zcpmap.protocol.HandshakeSubPhase
import dev.zcpmap.protocol.LifecycleEvent
import dev.zcpmap.protocol.LifecyclePhase
import dev.zcpmap.protocol.LifecycleState
import dev.zcpmap.protocol.MerkleTree
import dev.zcpmap.protocol.MerkleVerdict
import dev.zcpmap.protocol.MerkleVerifier
import dev.zcpmap.protocol.SessionId
import dev.zcpmap.protocol.SessionLifecycle
import dev.zcpmap.protocol.TeardownReason
import dev.zcpmap.protocol.Transition
import dev.zcpmap.protocol.WireConstants
import dev.zcpmap.protocol.WireFrame
import dev.zcpmap.protocol.WireProtocolCodec
import dev.zcpmap.protocol.toHex
import dev.zcpmap.security.CapabilityAction
import dev.zcpmap.security.CapabilityGrant
import dev.zcpmap.security.CapabilityManifest
import dev.zcpmap.security.CapabilityRequest
import dev.zcpmap.security.CapabilityToken
import dev.zcpmap.security.CommittedFact
import dev.zcpmap.security.CryptoEngine
import dev.zcpmap.security.CryptoError
import dev.zcpmap.security.CryptoResult
import dev.zcpmap.security.HandshakeResult
import dev.zcpmap.security.HandshakeStateMachine
import dev.zcpmap.security.HandshakeStep
import dev.zcpmap.security.HardwareSummary
import dev.zcpmap.security.IdentitySigner
import dev.zcpmap.security.NonceReplayCache
import dev.zcpmap.security.PeerIdentityPolicy
import dev.zcpmap.security.SecretBytes
import dev.zcpmap.security.SettlementReceipt
import dev.zcpmap.security.StaticKeyRotator
import dev.zcpmap.security.TokenVerdict
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/*
 * MeshSessionCoordinator owns every peer session and drives the full ZCP1 lifecycle:
 *
 *   discovery -> link -> Noise XX -> UWB secure ranging keyed from the Noise exporter
 *   (distance bound + cross-check) -> signed capability manifests -> contracts -> Merkle-verified
 *   streaming with capability tokens -> signed settlement -> teardown with key zeroization.
 *
 * Invariants enforced here (independent of anything the LLM decides):
 *   - No non-handshake frame is processed before the handshake completes.
 *   - Every post-handshake frame is AEAD-authenticated with the header as AAD and passes the
 *     anti-replay window; any failure is an immediate cryptographic teardown.
 *   - No contract or payload is possible before ATTESTATION_VERIFIED (distance bound + manifest).
 *   - Ranging continues for the session lifetime; leaving the radius or losing ranging tears down.
 *   - Incoming transfers require a capability token we minted and verify byte-for-byte via Merkle
 *     proofs before anything is written; the final file is checked against the declared SHA-256.
 */

sealed interface MeshCommandResult<out T> {
    data class Ok<T>(val value: T) : MeshCommandResult<T>
    data class Failed(val reason: String) : MeshCommandResult<Nothing>
}

data class SessionAttestation(
    val peerId: String,
    val phase: LifecyclePhase,
    val handshakeComplete: Boolean,
    val transportKeysLive: Boolean,
    val peerFingerprint: String?,
    val manifestExpiresAtSeconds: Long?,
    val distanceBound: Boolean,
    val boundDistanceMeters: Double?,
    val lastFixAgeMillis: Long?,
    val lastDistanceMeters: Double?,
    val executingContractId: String?,
)

data class TransferSummary(
    val contractId: String,
    val transferIdHex: String,
    val bytes: Long,
    val chunks: Int,
    val merkleRootHex: String,
    val settlementReceiptHashHex: String?,
)

data class PendingApproval(val approvalId: String, val contractId: String, val peerId: String, val summary: String)

class MeshSessionCoordinator(
    private val transport: PeerTransport,
    private val ranging: SecureRangingPort,
    private val identity: IdentitySigner,
    private val rotator: StaticKeyRotator,
    private val sandbox: SandboxFileStore,
    private val device: DeviceConstraintsPort,
    val policy: MeshPolicy,
    private val agentModel: String,
    private val scope: CoroutineScope,
    private val clock: () -> Long = System::currentTimeMillis,
    private val identityPolicy: PeerIdentityPolicy = PeerIdentityPolicy.ADMIT_ALL,
) {
    val localFingerprint: String = CryptoEngine.fingerprint(identity.publicKey)
    val identityHardwareBacked: Boolean = identity.securityLevel.hardwareBacked

    private val peerIdSalt = CryptoEngine.randomBytes(16)
    private val _events = MutableSharedFlow<MeshEvent>(extraBufferCapacity = 512, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    val events: SharedFlow<MeshEvent> = _events.asSharedFlow()
    private val _peers = MutableStateFlow<Map<String, PeerSnapshot>>(emptyMap())
    val peers: StateFlow<Map<String, PeerSnapshot>> = _peers.asStateFlow()
    private val _approvals = MutableStateFlow<List<PendingApproval>>(emptyList())
    val approvals: StateFlow<List<PendingApproval>> = _approvals.asStateFlow()

    private data class Discovered(val endpointId: String, val beaconToken: String)

    private val discovered = ConcurrentHashMap<String, Discovered>()
    private val sessions = ConcurrentHashMap<String, PeerSession>()
    private val contracts = ConcurrentHashMap<String, ContractRecord>()
    private val manifestReplay = NonceReplayCache { clock() / 1000 }
    private val evaluator = ContractEvaluator(policy)
    private var discoveryJob: Job? = null
    private var currentBeacon: String? = null

    private fun nowSeconds() = clock() / 1000

    fun peerIdFor(endpointId: String): String =
        "peer-" + CryptoEngine.hmacSha256(peerIdSalt, endpointId.toByteArray()).copyOf(8).toHex()

    // ======================================================================================
    // Lifecycle of the coordinator
    // ======================================================================================

    fun start() {
        if (discoveryJob?.isActive == true) return
        discoveryJob = scope.launch {
            launch {
                transport.discovery.collect { ev ->
                    when (ev) {
                        is DiscoveryEvent.PeerFound -> {
                            val pid = peerIdFor(ev.endpointId)
                            if (discovered.put(pid, Discovered(ev.endpointId, ev.beaconToken)) == null) {
                                _events.tryEmit(MeshEvent.PeerDiscovered(pid))
                            }
                            publishSnapshots()
                        }
                        is DiscoveryEvent.PeerLost -> {
                            val pid = peerIdFor(ev.endpointId)
                            discovered.remove(pid)
                            if (!sessions.containsKey(pid)) _events.tryEmit(MeshEvent.PeerLost(pid))
                            publishSnapshots()
                        }
                        is DiscoveryEvent.InboundLink -> acceptInbound(ev)
                    }
                }
            }
            // Beacon rotation: re-advertise whenever the 15-minute epoch rolls over.
            while (isActive) {
                val beacon = rotator.current().beaconToken
                if (beacon != currentBeacon) {
                    if (currentBeacon != null) transport.stopDiscovery()
                    transport.startDiscovery(beacon)
                    currentBeacon = beacon
                }
                delay(30_000)
            }
        }
    }

    suspend fun stop() {
        discoveryJob?.cancel()
        discoveryJob = null
        currentBeacon = null
        transport.stopDiscovery()
        sessions.values.toList().forEach { it.teardown(TeardownReason.LOCAL_REQUEST, "mesh stopped", notifyPeer = true) }
        discovered.clear()
        publishSnapshots()
    }

    fun discoveredPeerIds(): List<String> = (discovered.keys + sessions.keys).distinct().sorted()

    fun attestation(peerId: String): SessionAttestation? = sessions[peerId]?.attestation()

    fun contract(contractId: String): ContractRecord? = contracts[contractId]

    fun outboxFiles(): List<Pair<String, Long>> = sandbox.listOutbox()

    fun contractsFor(peerId: String): List<ContractRecord> = contracts.values.filter { it.peerId == peerId }.sortedBy { it.createdAtSeconds }

    fun peerManifest(peerId: String): CapabilityManifest? = sessions[peerId]?.peerManifest

    fun evaluate(contractId: String): MeshCommandResult<EvaluationReport> {
        val c = contracts[contractId] ?: return MeshCommandResult.Failed("unknown contract")
        val s = sessions[c.peerId] ?: return MeshCommandResult.Failed("no live session for contract peer")
        return MeshCommandResult.Ok(evaluator.evaluate(c, device.current(), s.peerManifest, nowSeconds()))
    }

    private fun acceptInbound(ev: DiscoveryEvent.InboundLink) {
        val pid = peerIdFor(ev.endpointId)
        discovered[pid] = Discovered(ev.endpointId, ev.beaconToken)
        val existing = sessions[pid]
        if (existing != null && existing.state !is LifecycleState.Teardown) {
            scope.launch { ev.link.close() }
            return
        }
        if (activeSessionCount() >= policy.maxConcurrentSessions) {
            scope.launch { ev.link.close() }
            _events.tryEmit(MeshEvent.Log(pid, LogChannel.TRANSPORT, "inbound link refused: session limit"))
            return
        }
        val s = PeerSession(pid, ev.endpointId, ev.beaconToken, HandshakeRole.RESPONDER, ev.link)
        sessions[pid] = s
        s.launch()
    }

    private fun activeSessionCount() = sessions.values.count { it.state !is LifecycleState.Teardown }

    /** Opens a link and runs the handshake through ATTESTATION_VERIFIED (or teardown). */
    suspend fun initiateHandshake(peerId: String, timeoutMillis: Long = 45_000): MeshCommandResult<SessionAttestation> {
        val d = discovered[peerId] ?: return MeshCommandResult.Failed("peer not discovered")
        sessions[peerId]?.let { s ->
            if (s.state !is LifecycleState.Teardown) return MeshCommandResult.Failed("session already exists in ${s.state.phase}")
        }
        if (activeSessionCount() >= policy.maxConcurrentSessions) return MeshCommandResult.Failed("session limit reached")
        val link = try {
            transport.connect(d.endpointId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return MeshCommandResult.Failed("link failed: ${e.message}")
        }
        val s = PeerSession(peerId, d.endpointId, d.beaconToken, HandshakeRole.INITIATOR, link)
        sessions[peerId] = s
        s.launch()
        return try {
            val final = withTimeout(timeoutMillis) { s.attested.await() }
            if (final is LifecycleState.AttestationVerified) MeshCommandResult.Ok(s.attestation())
            else MeshCommandResult.Failed("session ended in ${final.phase}")
        } catch (e: TimeoutCancellationException) {
            s.teardown(TeardownReason.TIMEOUT, "handshake did not complete in ${timeoutMillis}ms", notifyPeer = true)
            MeshCommandResult.Failed("timeout")
        }
    }

    suspend fun proposeContract(peerId: String, terms: ContractTerms, counterOf: String? = null): MeshCommandResult<ContractRecord> {
        val s = sessions[peerId] ?: return MeshCommandResult.Failed("no session with $peerId")
        return s.propose(terms, counterOf)
    }

    suspend fun respondToContract(contractId: String, decision: ContractDecision, reasonCode: String, counterTerms: ContractTerms?): MeshCommandResult<ContractRecord> {
        val c = contracts[contractId] ?: return MeshCommandResult.Failed("unknown contract")
        val s = sessions[c.peerId] ?: return MeshCommandResult.Failed("no session with contract peer")
        return s.respond(contractId, decision, reasonCode, counterTerms, userApproved = false)
    }

    /** Called from the UI when a human approves or denies a pending high-impact contract. */
    suspend fun resolveApproval(approvalId: String, approve: Boolean): MeshCommandResult<ContractRecord> {
        val a = _approvals.value.firstOrNull { it.approvalId == approvalId } ?: return MeshCommandResult.Failed("unknown approval")
        _approvals.value = _approvals.value.filterNot { it.approvalId == approvalId }
        val s = sessions[a.peerId] ?: return MeshCommandResult.Failed("session gone")
        return if (approve) s.respond(a.contractId, ContractDecision.ACCEPT, "user_approved", null, userApproved = true)
        else s.respond(a.contractId, ContractDecision.REJECT, "user_denied", null, userApproved = true)
    }

    suspend fun streamPayload(peerId: String, contractId: String, relativePath: String, timeoutMillis: Long = 30 * 60_000): MeshCommandResult<TransferSummary> {
        val s = sessions[peerId] ?: return MeshCommandResult.Failed("no session with $peerId")
        return try {
            withTimeout(timeoutMillis) { s.streamOutbound(contractId, relativePath) }
        } catch (e: TimeoutCancellationException) {
            s.teardown(TeardownReason.TIMEOUT, "transfer timed out", notifyPeer = true)
            MeshCommandResult.Failed("transfer timed out")
        }
    }

    suspend fun terminate(peerId: String, reason: TeardownReason, detail: String): MeshCommandResult<Unit> {
        val s = sessions[peerId] ?: return MeshCommandResult.Failed("no session with $peerId")
        s.teardown(reason, detail, notifyPeer = true)
        return MeshCommandResult.Ok(Unit)
    }

    private fun publishSnapshots() {
        val map = LinkedHashMap<String, PeerSnapshot>()
        for ((pid, d) in discovered) {
            if (!sessions.containsKey(pid)) {
                map[pid] = PeerSnapshot(pid, d.endpointId, d.beaconToken, LifecycleState.Idle, null, null, null, null, null, null, null, false, emptyList())
            }
        }
        for ((pid, s) in sessions) map[pid] = s.snapshot()
        _peers.value = map
    }

    private fun localManifestGrants(dc: DeviceConstraints): List<CapabilityGrant> {
        val headroom = (dc.freeStorageBytes - policy.storageReserveBytes).coerceAtLeast(0)
        val recvBytes = minOf(policy.maxTransferBytes, headroom)
        val grants = ArrayList<CapabilityGrant>()
        grants += CapabilityGrant(CapabilityAction.DATA_RECEIVE, "zcp:sandbox/inbox", recvBytes, 0, 0)
        grants += CapabilityGrant(CapabilityAction.DATA_SEND, "zcp:sandbox/outbox", policy.maxTransferBytes, 0, 0)
        val workOk = dc.thermal.severity <= policy.maxThermalForWork.severity &&
            (dc.charging || dc.batteryPercent >= policy.minBatteryPercentForWork)
        if (workOk) {
            grants += CapabilityGrant(CapabilityAction.COMPUTE_OFFLOAD, "zcp:sandbox/compute", recvBytes, policy.maxCpuMillisPerContract, 512)
            grants += CapabilityGrant(CapabilityAction.INFERENCE_SHARD, "zcp:sandbox/inference", recvBytes, policy.maxCpuMillisPerContract, 1024)
        }
        return grants
    }

    private fun hardwareSummary(dc: DeviceConstraints): HardwareSummary {
        val battery = when {
            dc.batteryPercent < 20 -> "0-19"; dc.batteryPercent < 50 -> "20-49"; dc.batteryPercent < 80 -> "50-79"; else -> "80-100"
        }
        val gib = 1L shl 30
        val storage = when {
            dc.freeStorageBytes < gib -> "<1GiB"; dc.freeStorageBytes < 10 * gib -> "1-10GiB"
            dc.freeStorageBytes < 100 * gib -> "10-100GiB"; else -> ">100GiB"
        }
        val (bc, bSalt) = CommittedFact.commit(battery, dc.batteryPercent.toString())
        val (sc, sSalt) = CommittedFact.commit(storage, dc.freeStorageBytes.toString())
        bSalt.fill(0); sSalt.fill(0) // openings are not retained: we never intend to disclose exact values
        return HardwareSummary(battery, dc.charging, dc.thermal.wire, storage, bc, sc)
    }

    // ======================================================================================
    // Per-peer session
    // ======================================================================================

    private inner class OutboundTransfer(val transferId: ByteArray, val contractId: String, val chunkCount: Int) {
        val accepted = CompletableDeferred<MeshMessage.TransferAccept>()
        val completed = CompletableDeferred<MeshMessage.TransferComplete>()
        @Volatile var ackedThrough = 0
        @Volatile var nack: AckBody.ChunkNack? = null
        @Volatile var aborted = false
        /** Bumped on every ack/nack/abort so waiters re-evaluate their predicate. */
        val signal = MutableStateFlow(0L)
        fun bump() { signal.value = signal.value + 1 }
    }

    private inner class InboundTransfer(
        val offer: MeshMessage.TransferOffer,
        val file: SandboxFileStore.InboundFile,
    ) {
        var nextExpected = 0
    }

    private inner class PeerSession(
        val peerId: String,
        val endpointId: String,
        val beaconToken: String,
        val role: HandshakeRole,
        val primaryLink: FrameLink,
    ) {
        private val lock = Mutex()
        private val sendLock = Mutex()
        private val codec = WireProtocolCodec(WireConstants.NEARBY_MAX_PAYLOAD)

        @Volatile var state: LifecycleState = LifecycleState.Idle
        val attested = CompletableDeferred<LifecycleState>()
        private val jobs = ArrayList<Job>()

        private var sessionId: SessionId? = null
        private var validator: FrameSequenceValidator? = null
        private var handshake: HandshakeStateMachine? = null
        private var result: HandshakeResult? = null
        private var macaroonRoot: SecretBytes? = null
        @Volatile private var bulkLink: FrameLink? = null

        private var prepared: PreparedRanging? = null
        private var peerUwb: MeshMessage.UwbParams? = null
        private var provisionedSts: Boolean? = null
        private var rangingConfig: BoundRangingConfig? = null
        private val boundingSamples = ArrayList<Double>()
        private var localRangeResult: MeshMessage.UwbResult? = null
        private var peerRangeResult: MeshMessage.UwbResult? = null
        private val recentDistances = ArrayDeque<Double>()
        @Volatile private var lastFix: RadarFix? = null
        private var boundDistance: Double? = null

        @Volatile var peerManifest: CapabilityManifest? = null
        private var pendingPeerManifest: ByteArray? = null
        private var localManifestSentAtSeconds: Long? = null
        private var localManifestLifetime = 300L

        @Volatile private var lastRxMillis = clock()
        private var lastHeartbeatMillis = 0L

        private val outbound = ConcurrentHashMap<String, OutboundTransfer>()
        private val inbound = ConcurrentHashMap<String, InboundTransfer>()
        private val localReceipts = ConcurrentHashMap<String, SettlementReceipt>()
        private val peerReceipts = ConcurrentHashMap<String, SettlementReceipt>()
        private val settled = ConcurrentHashMap<String, CompletableDeferred<String>>()
        private val tornDown = java.util.concurrent.atomic.AtomicBoolean(false)

        fun launch() {
            applyInitial(LifecycleEvent.PeerDiscovered(endpointId))
            applyInitial(LifecycleEvent.LinkEstablished(role))
            publishSnapshots()
            jobs += scope.launch { readLoop(primaryLink) }
            jobs += scope.launch { watchdog() }
            if (role == HandshakeRole.INITIATOR) {
                jobs += scope.launch {
                    lock.withLock {
                        val sid = SessionId.random(CryptoEngine::randomBytes)
                        sessionId = sid
                        validator = FrameSequenceValidator(sid)
                        val hs = HandshakeStateMachine.initiator(sid, rotator.current(), identityPolicy, clock)
                        handshake = hs
                        when (val step = hs.start()) {
                            is HandshakeStep.Send -> sendHandshake(step.message, step.sequence)
                            is HandshakeStep.Failed -> violationLocked(TeardownReason.AUTHENTICATION_FAILED, step.error.message ?: "handshake start failed")
                            is HandshakeStep.Complete -> violationLocked(TeardownReason.PROTOCOL_VIOLATION, "impossible handshake step")
                        }
                    }
                }
            }
            publishSnapshots()
        }

        // ------------------------------------------------------------------ reading

        private suspend fun readLoop(link: FrameLink) {
            try {
                link.incoming.collect { bytes ->
                    lastRxMillis = clock()
                    lock.withLock { if (!tornDown.get()) handleDatagram(bytes) }
                }
                if (!tornDown.get()) teardown(TeardownReason.LINK_LOST, "link ${link.linkId} closed", notifyPeer = false)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (!tornDown.get()) teardown(TeardownReason.LINK_LOST, "link error: ${e.javaClass.simpleName}", notifyPeer = false)
            }
        }

        private suspend fun handleDatagram(bytes: ByteArray) {
            val frame = when (val r = codec.decodeDatagram(bytes)) {
                is DecodeResult.Frame -> r.frame
                is DecodeResult.Malformed -> return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "malformed frame: ${r.reason}")
                DecodeResult.NeedMoreData -> return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "truncated frame")
            }
            val h = frame.header
            if (h.type == FrameType.SECURITY_ABORT) return handleAbort(frame)

            if (sessionId == null) {
                // Responder: the first frame must be Noise message 1 with sequence 0.
                if (role != HandshakeRole.RESPONDER || h.type != FrameType.HANDSHAKE || h.sequence != 0L) {
                    return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "first frame must be handshake msg1")
                }
                sessionId = h.sessionId
                validator = FrameSequenceValidator(h.sessionId)
                handshake = HandshakeStateMachine.responder(h.sessionId, rotator.current(), identityPolicy, clock)
            }
            when (val v = validator!!.check(h)) {
                is FrameSequenceValidator.Verdict.Reject -> return violationLocked(TeardownReason.PROTOCOL_VIOLATION, v.reason)
                FrameSequenceValidator.Verdict.Accept -> Unit
            }

            if (h.type == FrameType.HANDSHAKE) return handleHandshakeFrame(frame)

            val res = result ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "${h.type} before handshake completion")
            val aad = codec.encodeHeader(h)
            val plaintext = when (val r = res.receiveCipher.open(h.sequence, aad, frame.sealedBody())) {
                is CryptoResult.Ok -> r.value
                is CryptoResult.Err -> return when (r.error) {
                    is CryptoError.ReplayDetected -> violationLocked(TeardownReason.REPLAY_DETECTED, "sequence ${h.sequence} replayed")
                    else -> violationLocked(TeardownReason.AUTHENTICATION_FAILED, r.error.message ?: "decrypt failed")
                }
            }
            try {
                dispatch(h, plaintext)
            } finally {
                plaintext.fill(0)
            }
        }

        private suspend fun dispatch(h: FrameHeader, plaintext: ByteArray) {
            when (h.type) {
                FrameType.UWB_BIND, FrameType.AGENT_PROPOSAL -> {
                    val msg = when (val p = MeshMessages.parse(plaintext)) {
                        is MeshMessages.Parsed.Ok -> p.message
                        is MeshMessages.Parsed.Rejected -> return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "peer message rejected: ${p.reason}")
                    }
                    if (!MeshMessages.allowedIn(msg, h.type)) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "message not allowed in ${h.type}")
                    handleMessage(msg)
                }
                FrameType.CAPABILITY_MANIFEST -> handleManifest(plaintext.copyOf())
                FrameType.PAYLOAD_CHUNK -> {
                    val body = ChunkBody.decode(plaintext) ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "malformed chunk")
                    handleChunk(body)
                }
                FrameType.HEARTBEAT_ACK -> {
                    val ack = AckBody.decode(plaintext) ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "malformed ack")
                    handleAck(ack)
                }
                FrameType.HANDSHAKE, FrameType.SECURITY_ABORT -> Unit
            }
        }

        private suspend fun handleAbort(frame: WireFrame) {
            val res = result
            val code: AbortCode = if (res == null) {
                // Pre-handshake aborts are unauthenticated by necessity; they can only end a session
                // that has not yet produced any secret, so honouring them leaks nothing.
                AbortCode.fromCode(frame.tag[0])
            } else {
                when (val r = res.receiveCipher.open(frame.header.sequence, codec.encodeHeader(frame.header), frame.sealedBody())) {
                    is CryptoResult.Ok -> AbortCode.fromCode(r.value.firstOrNull() ?: 0)
                    is CryptoResult.Err -> {
                        // Forged abort after keys exist: ignore it (prevents trivial spoofed-teardown DoS) but log.
                        _events.tryEmit(MeshEvent.Log(peerId, LogChannel.CRYPTO, "ignored unauthenticated SECURITY_ABORT"))
                        return
                    }
                }
            }
            teardownLocked(TeardownReason.PEER_ABORT, "peer aborted: $code", notifyPeer = false)
        }

        // ------------------------------------------------------------------ handshake

        private suspend fun handleHandshakeFrame(frame: WireFrame) {
            val st = state
            if (st !is LifecycleState.NoiseHandshake || st.subPhase != HandshakeSubPhase.NOISE_EXCHANGE || result != null) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "handshake frame outside NOISE_EXCHANGE")
            }
            val hs = handshake ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "no handshake state")
            validator!!.advanceHandshake()
            when (val step = hs.onMessage(frame.payload + frame.tag)) {
                is HandshakeStep.Send -> {
                    validator!!.advanceHandshake()
                    sendHandshake(step.message, step.sequence)
                }
                is HandshakeStep.Complete -> {
                    step.finalMessage?.let {
                        validator!!.advanceHandshake()
                        sendHandshake(it, step.finalSequence)
                    }
                    onHandshakeComplete(step.result)
                }
                is HandshakeStep.Failed -> violationLocked(TeardownReason.AUTHENTICATION_FAILED, "noise: ${step.error.message}")
            }
        }

        private suspend fun sendHandshake(message: ByteArray, sequence: Long) {
            val (payload, tag) = WireProtocolCodec.splitHandshakeMessage(message)
            val header = FrameHeader(WireConstants.PROTOCOL_VERSION, FrameType.HANDSHAKE, sessionId!!, sequence, payload.size)
            if (role == HandshakeRole.INITIATOR && sequence == 0L) validator!!.advanceHandshake()
            rawSend(codec.encode(WireFrame(header, payload, tag)), bulk = false)
        }

        private suspend fun onHandshakeComplete(res: HandshakeResult) {
            result = res
            handshake = null
            macaroonRoot = res.deriveSecret("macaroon-root", 32)
            log(LogChannel.CRYPTO, "Noise XX complete; peer ${res.remoteFingerprint}; h=${res.handshakeHash.copyOf(8).toHex()}")
            apply(LifecycleEvent.NoiseCompleted)
            if (tornDown.get()) return
            beginDistanceBounding()
        }

        // ------------------------------------------------------------------ distance bounding

        private suspend fun beginDistanceBounding() {
            if (!ranging.isAvailable) {
                if (policy.requireUwb) return violationLocked(TeardownReason.POLICY_VIOLATION, "UWB unavailable; policy requires distance bounding")
                log(LogChannel.RANGING, "UWB unavailable; policy allows UNBOUNDED session")
                boundDistance = -1.0
                apply(LifecycleEvent.DistanceBoundVerified(-1.0))
                return sendLocalManifest()
            }
            val p = try {
                ranging.prepare(role)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                return violationLocked(TeardownReason.RANGING_LOST, "UWB prepare failed: ${e.message}")
            }
            prepared = p
            sendEncrypted(
                FrameType.UWB_BIND,
                MeshMessages.encode(
                    MeshMessage.UwbParams(
                        p.local.address,
                        if (role == HandshakeRole.INITIATOR) p.local.channel else null,
                        if (role == HandshakeRole.INITIATOR) p.local.preambleIndex else null,
                        p.local.supportsProvisionedSts,
                        p.local.supportsAngleOfArrival,
                    ),
                ),
            )
            maybeStartRanging()
        }

        private suspend fun handleUwbParams(m: MeshMessage.UwbParams) {
            val st = state
            if (st !is LifecycleState.NoiseHandshake || st.subPhase != HandshakeSubPhase.DISTANCE_BOUNDING || peerUwb != null) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "unexpected uwb_params")
            }
            if (role == HandshakeRole.RESPONDER && (m.channel == null || m.preamble == null)) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "controller did not assign a UWB channel")
            }
            if (role == HandshakeRole.INITIATOR && (m.channel != null || m.preamble != null)) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "controlee tried to assign a UWB channel")
            }
            peerUwb = m
            maybeStartRanging()
        }

        private suspend fun maybeStartRanging() {
            val p = prepared ?: return
            val peer = peerUwb ?: return
            val res = result ?: return
            if (rangingConfig != null) return
            val psts = p.local.supportsProvisionedSts && peer.provisionedSts
            if (!psts && policy.requireProvisionedSts) {
                return violationLocked(TeardownReason.POLICY_VIOLATION, "provisioned STS unsupported by one side; static STS is refused")
            }
            provisionedSts = psts
            val channel = if (role == HandshakeRole.INITIATOR) p.local.channel else peer.channel
            val preamble = if (role == HandshakeRole.INITIATOR) p.local.preambleIndex else peer.preamble
            if (channel == null || preamble == null) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "UWB channel unresolved")
            val sidBytes = res.deriveSecret("uwb-session-id", 4)
            val uwbSessionId = sidBytes.withCopy { ByteBuffer.wrap(it).int and 0x7FFF_FFFF }.let { if (it == 0) 1 else it }
            sidBytes.close()
            val stsKey = res.deriveSecret("uwb-sts-key", 16)
            val cfg = stsKey.withCopy { k -> BoundRangingConfig(uwbSessionId, k, peer.address, channel, preamble, psts) }
            stsKey.close()
            rangingConfig = cfg
            log(LogChannel.RANGING, "secure ranging start: session=$uwbSessionId ch=$channel pre=$preamble psts=$psts")
            jobs += scope.launch { rangingLoop(p, cfg) }
        }

        private suspend fun rangingLoop(p: PreparedRanging, cfg: BoundRangingConfig) {
            try {
                p.start(cfg).collect { ev ->
                    when (ev) {
                        is RangingEvent.Sample -> {
                            val d = ev.distanceMeters ?: return@collect
                            if (d.isNaN() || d < 0) return@collect
                            val fix = RadarFix(d, ev.azimuthDegrees, ev.elevationDegrees, clock())
                            lastFix = fix
                            _events.tryEmit(MeshEvent.Ranging(peerId, fix))
                            lock.withLock { if (!tornDown.get()) onRangingSample(d) }
                        }
                        is RangingEvent.Dropout -> log(LogChannel.RANGING, "ranging dropout: ${ev.reason}")
                        is RangingEvent.Failure -> {
                            lock.withLock { violationLocked(TeardownReason.RANGING_LOST, "ranging failure: ${ev.reason}") }
                            return@collect
                        }
                    }
                }
                if (!tornDown.get()) lock.withLock { violationLocked(TeardownReason.RANGING_LOST, "ranging session ended") }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (!tornDown.get()) lock.withLock { violationLocked(TeardownReason.RANGING_LOST, "ranging error: ${e.message}") }
            }
        }

        private suspend fun onRangingSample(d: Double) {
            val st = state
            if (st is LifecycleState.NoiseHandshake && st.subPhase == HandshakeSubPhase.DISTANCE_BOUNDING) {
                if (localRangeResult != null) return
                boundingSamples += d
                if (boundingSamples.size >= policy.minRangingSamples) {
                    val sorted = boundingSamples.sorted()
                    val median = sorted[sorted.size / 2]
                    val withinFraction = boundingSamples.count { it <= policy.maxDistanceMeters }.toDouble() / boundingSamples.size
                    val within = median <= policy.maxDistanceMeters && withinFraction >= 0.75
                    val r = MeshMessage.UwbResult((median * 100).toLong(), boundingSamples.size, within)
                    localRangeResult = r
                    sendEncrypted(FrameType.UWB_BIND, MeshMessages.encode(r))
                    tryCompleteDistanceBound()
                }
                return
            }
            // Continuous enforcement after the bound is established.
            recentDistances.addLast(d)
            while (recentDistances.size > 5) recentDistances.removeFirst()
            if (recentDistances.size == 5) {
                val median = recentDistances.sorted()[2]
                if (median > policy.maxDistanceMeters * 1.2) {
                    violationLocked(TeardownReason.DISTANCE_BOUND_EXCEEDED, "peer left the ${policy.maxDistanceMeters}m radius (median %.2fm)".format(median))
                }
            }
        }

        private suspend fun handleUwbResult(m: MeshMessage.UwbResult) {
            val st = state
            if (st !is LifecycleState.NoiseHandshake || st.subPhase != HandshakeSubPhase.DISTANCE_BOUNDING || peerRangeResult != null) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "unexpected uwb_result")
            }
            peerRangeResult = m
            tryCompleteDistanceBound()
        }

        private suspend fun tryCompleteDistanceBound() {
            val mine = localRangeResult ?: return
            val theirs = peerRangeResult ?: return
            if (!mine.withinBound) return violationLocked(TeardownReason.DISTANCE_BOUND_EXCEEDED, "local median ${mine.medianCentimeters}cm exceeds bound")
            if (!theirs.withinBound) return violationLocked(TeardownReason.DISTANCE_BOUND_EXCEEDED, "peer median ${theirs.medianCentimeters}cm exceeds bound")
            val diffM = kotlin.math.abs(mine.medianCentimeters - theirs.medianCentimeters) / 100.0
            if (diffM > policy.crossCheckToleranceMeters) {
                return violationLocked(TeardownReason.DISTANCE_BOUND_EXCEEDED, "distance cross-check failed (Δ=%.2fm): possible relay".format(diffM))
            }
            val meters = mine.medianCentimeters / 100.0
            boundDistance = meters
            log(LogChannel.RANGING, "distance bound verified: %.2fm (peer %.2fm)".format(meters, theirs.medianCentimeters / 100.0))
            apply(LifecycleEvent.DistanceBoundVerified(meters))
            if (tornDown.get()) return
            sendLocalManifest()
            pendingPeerManifest?.let { pendingPeerManifest = null; handleManifest(it) }
        }

        // ------------------------------------------------------------------ attestation

        private suspend fun sendLocalManifest() {
            val res = result ?: return
            val dc = device.current()
            val m = CapabilityManifest.create(
                signer = identity,
                audienceFingerprint = res.remoteFingerprint,
                handshakeHash = res.handshakeHash,
                capabilities = localManifestGrants(dc),
                hardware = hardwareSummary(dc),
                agentModel = agentModel,
                nowSeconds = nowSeconds(),
                lifetimeSeconds = localManifestLifetime,
            )
            sendEncrypted(FrameType.CAPABILITY_MANIFEST, CapabilityManifest.sign(m, identity))
            localManifestSentAtSeconds = nowSeconds()
        }

        private suspend fun handleManifest(bytes: ByteArray) {
            val res = result ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "manifest before handshake")
            val st = state
            val inExchange = st is LifecycleState.NoiseHandshake && st.subPhase == HandshakeSubPhase.MANIFEST_EXCHANGE
            val early = st is LifecycleState.NoiseHandshake && st.subPhase == HandshakeSubPhase.DISTANCE_BOUNDING
            val refresh = st.phase in setOf(
                LifecyclePhase.ATTESTATION_VERIFIED, LifecyclePhase.AGENT_NEGOTIATING,
                LifecyclePhase.TASK_EXECUTING, LifecyclePhase.SETTLEMENT_COMPLETE,
            )
            if (early) {
                if (pendingPeerManifest != null) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "duplicate early manifest")
                pendingPeerManifest = bytes
                return
            }
            if (!inExchange && !refresh) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "manifest in ${st.phase}")
            val verified = CapabilityManifest.verify(bytes, res.remoteIdentityPublicKey, localFingerprint, res.handshakeHash, nowSeconds(), manifestReplay)
            when (verified) {
                is CryptoResult.Err -> return violationLocked(TeardownReason.ATTESTATION_INVALID, verified.error.message ?: "manifest invalid")
                is CryptoResult.Ok -> peerManifest = verified.value
            }
            log(LogChannel.CRYPTO, "peer manifest verified (exp ${verified.value.expiresAtSeconds}, ${verified.value.capabilities.size} grants)")
            if (inExchange) {
                apply(LifecycleEvent.ManifestVerified(res.remoteFingerprint))
                if (state is LifecycleState.AttestationVerified) {
                    attested.complete(state)
                    jobs += scope.launch { tryOpenBulkLink() }
                }
            }
            publishSnapshots()
        }

        private suspend fun tryOpenBulkLink() {
            val res = result ?: return
            val token = res.deriveSecret("wifi-aware-match", 8)
            val psk = res.deriveSecret("wifi-aware-psk", 32)
            val params = token.withCopy { t -> psk.withCopy { p -> BulkLinkParams(t.copyOf(), CryptoEngine.b64url(p)) } }
            token.close(); psk.close()
            val link = try {
                transport.openBulkLink(endpointId, role, params)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                log(LogChannel.TRANSPORT, "Wi-Fi Aware unavailable: ${e.message}")
                null
            } finally {
                params.matchToken.fill(0)
            } ?: return
            if (tornDown.get()) { link.close(); return }
            bulkLink = link
            log(LogChannel.TRANSPORT, "Wi-Fi Aware bulk link up (${link.linkId})")
            jobs += scope.launch { readLoop(link) }
            publishSnapshots()
        }

        // ------------------------------------------------------------------ contracts

        suspend fun propose(terms: ContractTerms, counterOf: String?): MeshCommandResult<ContractRecord> = lock.withLock {
            val st = state
            if (st !is LifecycleState.AttestationVerified && st !is LifecycleState.AgentNegotiating && st !is LifecycleState.SettlementComplete) {
                return@withLock MeshCommandResult.Failed("cannot propose in ${st.phase}")
            }
            val res = result ?: return@withLock MeshCommandResult.Failed("no keys")
            val now = nowSeconds()
            val cid = "ctr-" + CryptoEngine.randomBytes(8).toHex()
            val record = ContractRecord(
                contractId = cid, peerId = peerId, origin = ContractOrigin.LOCAL,
                terms = terms.copy(summary = UntrustedText.sanitize(terms.summary)),
                status = ContractStatus.PROPOSED, createdAtSeconds = now,
                expiresAtSeconds = now + policy.contractTtlSeconds, counterOf = counterOf,
            )
            val report = evaluator.evaluate(record, device.current(), peerManifest, now)
            if (report.verdict == Feasibility.INFEASIBLE) {
                return@withLock MeshCommandResult.Failed("infeasible: " + report.reasons.joinToString("; "))
            }
            val inboundToken = if (record.localReceives) mintInboundToken(res, cid, terms.maxBytes, record.expiresAtSeconds + terms.durationSeconds) else null
            apply(LifecycleEvent.ContractOpened(cid))
            if (tornDown.get()) return@withLock MeshCommandResult.Failed("session torn down")
            contracts[cid] = record
            sendEncrypted(
                FrameType.AGENT_PROPOSAL,
                MeshMessages.encode(MeshMessage.ContractProposal(cid, record.terms, record.expiresAtSeconds, inboundToken, counterOf)),
            )
            log(LogChannel.PROTOCOL, "proposed $cid (${terms.taskType.wire}, ${terms.maxBytes} bytes, ${terms.direction.wire})")
            MeshCommandResult.Ok(record)
        }

        suspend fun respond(
            contractId: String,
            decision: ContractDecision,
            reasonCode: String,
            counterTerms: ContractTerms?,
            userApproved: Boolean,
        ): MeshCommandResult<ContractRecord> {
            val counterResult: MeshCommandResult<ContractRecord>
            lock.withLock {
                val c = contracts[contractId] ?: return MeshCommandResult.Failed("unknown contract")
                if (c.peerId != peerId || c.origin != ContractOrigin.REMOTE) return MeshCommandResult.Failed("not an incoming contract for this peer")
                val allowed = if (userApproved) setOf(ContractStatus.AWAITING_USER_APPROVAL) else setOf(ContractStatus.PROPOSED)
                if (c.status !in allowed) return MeshCommandResult.Failed("contract is ${c.status}")
                val res = result ?: return MeshCommandResult.Failed("no keys")
                val st = state
                if (st !is LifecycleState.AgentNegotiating) return MeshCommandResult.Failed("cannot respond in ${st.phase}")
                if (contractId !in st.openContractIds) return MeshCommandResult.Failed("contract is no longer open")
                when (decision) {
                    ContractDecision.ACCEPT -> {
                        val report = evaluator.evaluate(c, device.current(), peerManifest, nowSeconds())
                        when (report.verdict) {
                            Feasibility.INFEASIBLE -> return MeshCommandResult.Failed("infeasible: " + report.reasons.joinToString("; "))
                            Feasibility.NEEDS_USER_APPROVAL -> if (!userApproved) {
                                val updated = c.copy(status = ContractStatus.AWAITING_USER_APPROVAL)
                                contracts[contractId] = updated
                                val approvalId = "apr-" + CryptoEngine.randomBytes(6).toHex()
                                val summary = "${c.terms.taskType.wire}: ${c.terms.maxBytes} bytes, ${c.terms.cpuMillis} ms cpu, ${c.terms.direction.wire}"
                                _approvals.value = _approvals.value + PendingApproval(approvalId, contractId, peerId, summary)
                                _events.tryEmit(MeshEvent.ApprovalRequired(peerId, approvalId, summary))
                                return MeshCommandResult.Ok(updated)
                            }
                            Feasibility.FEASIBLE -> Unit
                        }
                        val token = if (c.localReceives) mintInboundToken(res, contractId, c.terms.maxBytes, c.expiresAtSeconds + c.terms.durationSeconds) else null
                        if (!c.localReceives && c.outboundToken == null) return MeshCommandResult.Failed("peer supplied no token for us to send with")
                        apply(LifecycleEvent.ContractAccepted(contractId))
                        if (tornDown.get()) return MeshCommandResult.Failed("session torn down")
                        val updated = c.copy(status = ContractStatus.ACCEPTED)
                        contracts[contractId] = updated
                        sendEncrypted(FrameType.AGENT_PROPOSAL, MeshMessages.encode(MeshMessage.ContractResponse(contractId, ContractDecision.ACCEPT, sanitizeReason(reasonCode), token)))
                        log(LogChannel.PROTOCOL, "accepted $contractId")
                        return MeshCommandResult.Ok(updated)
                    }
                    ContractDecision.REJECT, ContractDecision.COUNTER -> {
                        apply(LifecycleEvent.ContractDeclined(contractId))
                        val updated = c.copy(status = ContractStatus.REJECTED)
                        contracts[contractId] = updated
                        sendEncrypted(FrameType.AGENT_PROPOSAL, MeshMessages.encode(MeshMessage.ContractResponse(contractId, decision, sanitizeReason(reasonCode), null)))
                        if (decision == ContractDecision.REJECT) return MeshCommandResult.Ok(updated)
                    }
                }
            }
            // COUNTER: the counter-offer is a fresh proposal referencing the declined one.
            val terms = counterTerms ?: return MeshCommandResult.Failed("counter requires counter terms")
            counterResult = propose(terms, contractId)
            return counterResult
        }

        private fun sanitizeReason(r: String) = r.lowercase().filter { it in 'a'..'z' || it == '_' }.take(32).ifEmpty { "unspecified" }

        private fun mintInboundToken(res: HandshakeResult, cid: String, maxBytes: Long, expSeconds: Long): String {
            val root = macaroonRoot ?: throw CryptoError.KeyWiped()
            return CapabilityToken.mint(
                root,
                listOf(
                    "sid = ${sessionId!!}",
                    "aud = ${res.remoteFingerprint}",
                    "cid = $cid",
                    "op = push",
                    "exp <= $expSeconds",
                    "max_bytes <= $maxBytes",
                    "path_prefix prefix inbox/$cid",
                ),
            ).encode()
        }

        private suspend fun handleProposal(m: MeshMessage.ContractProposal) {
            val now = nowSeconds()
            val st = state
            val negotiable = st is LifecycleState.AttestationVerified || st is LifecycleState.AgentNegotiating || st is LifecycleState.SettlementComplete
            fun reply(reason: String) = MeshMessages.encode(MeshMessage.ContractResponse(m.contractId, ContractDecision.REJECT, reason, null))
            if (contracts.containsKey(m.contractId)) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "contract id reuse")
            if (!negotiable) return sendEncrypted(FrameType.AGENT_PROPOSAL, reply("busy"))
            if (st is LifecycleState.AgentNegotiating && st.openContractIds.size >= SessionLifecycle.MAX_OPEN_CONTRACTS) {
                return sendEncrypted(FrameType.AGENT_PROPOSAL, reply("too_many_open"))
            }
            if (m.expiresAtSeconds <= now || m.expiresAtSeconds - now > policy.contractTtlSeconds + 60) {
                return sendEncrypted(FrameType.AGENT_PROPOSAL, reply("bad_expiry"))
            }
            if (m.terms.direction == TransferDirection.ACCEPTOR_SENDS && m.inboundToken == null) {
                return sendEncrypted(FrameType.AGENT_PROPOSAL, reply("missing_token"))
            }
            if (m.terms.direction == TransferDirection.PROPOSER_SENDS && m.inboundToken != null) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "unsolicited token in proposal")
            }
            apply(LifecycleEvent.ContractOpened(m.contractId))
            if (tornDown.get()) return
            val record = ContractRecord(
                contractId = m.contractId, peerId = peerId, origin = ContractOrigin.REMOTE, terms = m.terms,
                status = ContractStatus.PROPOSED, createdAtSeconds = now, expiresAtSeconds = m.expiresAtSeconds,
                outboundToken = m.inboundToken, counterOf = m.counterOf,
            )
            contracts[m.contractId] = record
            log(LogChannel.PEER_UNTRUSTED, "proposal ${m.contractId}: ${m.terms.taskType.wire}, ${m.terms.maxBytes} bytes — \"${m.terms.summary.take(160)}\"")
            _events.tryEmit(MeshEvent.ContractProposed(peerId, record))
        }

        private suspend fun handleResponse(m: MeshMessage.ContractResponse) {
            val c = contracts[m.contractId]
            if (c == null || c.peerId != peerId || c.origin != ContractOrigin.LOCAL || c.status != ContractStatus.PROPOSED) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "response for unknown/closed contract")
            }
            val st = state
            if (st !is LifecycleState.AgentNegotiating || m.contractId !in st.openContractIds) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "response for a superseded contract ${m.contractId}")
            }
            when (m.decision) {
                ContractDecision.ACCEPT -> {
                    if (!c.localReceives && m.token == null) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "accept without token")
                    if (c.localReceives && m.token != null) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "unsolicited token in accept")
                    if (m.token != null && CapabilityToken.decode(m.token) == null) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "malformed token")
                    if (nowSeconds() >= c.expiresAtSeconds) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "acceptance after expiry")
                    apply(LifecycleEvent.ContractAccepted(m.contractId))
                    if (tornDown.get()) return
                    contracts[m.contractId] = c.copy(status = ContractStatus.ACCEPTED, outboundToken = m.token ?: c.outboundToken)
                }
                ContractDecision.REJECT, ContractDecision.COUNTER -> {
                    apply(LifecycleEvent.ContractDeclined(m.contractId))
                    contracts[m.contractId] = c.copy(status = ContractStatus.REJECTED)
                }
            }
            _events.tryEmit(MeshEvent.ContractAnswered(peerId, m.contractId, m.decision, m.reasonCode))
        }

        // ------------------------------------------------------------------ outbound transfer

        suspend fun streamOutbound(contractId: String, relativePath: String): MeshCommandResult<TransferSummary> = try {
            streamOutboundInner(contractId, relativePath)
        } catch (e: CancellationException) {
            throw e
        } catch (e: TransferAborted) {
            MeshCommandResult.Failed("transfer aborted: ${e.message}")
        } catch (e: CryptoError) {
            MeshCommandResult.Failed("crypto failure during transfer: ${e.message}")
        } catch (e: java.io.IOException) {
            markContract(contractId, ContractStatus.FAILED)
            MeshCommandResult.Failed("I/O failure: ${e.message}")
        }

        private suspend fun streamOutboundInner(contractId: String, relativePath: String): MeshCommandResult<TransferSummary> {
            val transfer: OutboundTransfer
            val file: java.io.File
            val tree: MerkleTree
            val fileSha: ByteArray
            val size: Long
            val chunkSize = policy.chunkSizeBytes
            lock.withLock {
                val st = state
                if (st !is LifecycleState.TaskExecuting || st.contractId != contractId) return MeshCommandResult.Failed("contract $contractId is not executing")
                val c = contracts[contractId] ?: return MeshCommandResult.Failed("unknown contract")
                if (c.localReceives) return MeshCommandResult.Failed("this contract has the peer sending, not us")
                if (c.status != ContractStatus.ACCEPTED) return MeshCommandResult.Failed("contract is ${c.status}")
                if (outbound.values.any { it.contractId == contractId }) return MeshCommandResult.Failed("transfer already running")
                file = when (val r = sandbox.resolveOutbound(relativePath)) {
                    is SandboxResult.Ok -> r.value
                    is SandboxResult.Denied -> return MeshCommandResult.Failed("sandbox: ${r.reason}")
                }
                size = file.length()
                if (size <= 0) return MeshCommandResult.Failed("empty file")
                if (size > c.terms.maxBytes) return MeshCommandResult.Failed("file is $size bytes; contract allows ${c.terms.maxBytes}")
                contracts[contractId] = c.copy(status = ContractStatus.EXECUTING)
            }
            // Hash pass outside the lock (may take a while for large files).
            val leafHashes = ArrayList<ByteArray>()
            val md = java.security.MessageDigest.getInstance("SHA-256")
            withContext(kotlinx.coroutines.Dispatchers.IO) {
                RandomAccessFile(file, "r").use { raf ->
                    val buf = ByteArray(chunkSize)
                    var off = 0L
                    while (off < size) {
                        val n = minOf(chunkSize.toLong(), size - off).toInt()
                        raf.readFully(buf, 0, n)
                        leafHashes += dev.zcpmap.protocol.MerkleHash.leaf(buf, 0, n)
                        md.update(buf, 0, n)
                        off += n
                    }
                }
            }
            tree = MerkleTree.fromLeafHashes(leafHashes)
            fileSha = md.digest()
            val count = leafHashes.size
            val tid = CryptoEngine.randomBytes(16)
            transfer = OutboundTransfer(tid, contractId, count)
            lock.withLock {
                val c = contracts[contractId] ?: return MeshCommandResult.Failed("contract vanished")
                val token = c.outboundToken ?: return MeshCommandResult.Failed("no capability token from peer")
                outbound[tid.toHex()] = transfer
                sendEncrypted(
                    FrameType.AGENT_PROPOSAL,
                    MeshMessages.encode(MeshMessage.TransferOffer(contractId, tid, size, chunkSize, count, tree.root, fileSha, token)),
                )
            }
            val accept = withTimeout(20_000) { transfer.accepted.await() }
            if (!accept.accepted) {
                outbound.remove(tid.toHex())
                markContract(contractId, ContractStatus.FAILED)
                return MeshCommandResult.Failed("peer refused transfer: ${accept.reasonCode}")
            }
            withContext(kotlinx.coroutines.Dispatchers.IO) {
                RandomAccessFile(file, "r").use { raf ->
                    for (i in 0 until count) {
                        // Backpressure: never more than sendWindowChunks unacknowledged chunks in flight.
                        transfer.signal.first { i - transfer.ackedThrough < policy.sendWindowChunks || transfer.nack != null || transfer.aborted }
                        transfer.nack?.let { throw TransferAborted("peer rejected chunk ${it.index} (code ${it.reasonCode})") }
                        if (transfer.aborted || tornDown.get()) throw TransferAborted("session torn down")
                        val off = i.toLong() * chunkSize
                        val n = minOf(chunkSize.toLong(), size - off).toInt()
                        val data = ByteArray(n)
                        raf.seek(off)
                        raf.readFully(data)
                        val body = ChunkBody(tid, i, count, tree.proof(i), data).encode()
                        sendEncrypted(FrameType.PAYLOAD_CHUNK, body, bulk = true)
                        if (i % 16 == 0 || i == count - 1) {
                            _events.tryEmit(MeshEvent.TransferProgress(peerId, contractId, tid.toHex(), minOf(off + n, size), size, inbound = false))
                        }
                    }
                }
            }
            val done = withTimeout(60_000) { transfer.completed.await() }
            outbound.remove(tid.toHex())
            if (!done.verified) {
                markContract(contractId, ContractStatus.FAILED)
                teardown(TeardownReason.PROTOCOL_VIOLATION, "peer could not verify transfer", notifyPeer = true)
                return MeshCommandResult.Failed("peer reported verification failure")
            }
            _events.tryEmit(MeshEvent.TransferCompleted(peerId, contractId, tid.toHex(), relativePath, inbound = false, merkleRootHex = tree.root.toHex()))
            val settledHash = completeSettlement(contractId, size, tree.root, fileSha)
            return MeshCommandResult.Ok(TransferSummary(contractId, tid.toHex(), size, count, tree.root.toHex(), settledHash))
        }

        private suspend fun completeSettlement(contractId: String, bytes: Long, root: ByteArray, resultHash: ByteArray): String? {
            val waiter = settled.getOrPut(contractId) { CompletableDeferred() }
            lock.withLock {
                val res = result ?: return null
                val receipt = SettlementReceipt.issue(identity, contractId, res.handshakeHash, bytes, root, resultHash, "fulfilled", nowSeconds())
                localReceipts[contractId] = receipt
                sendEncrypted(FrameType.AGENT_PROPOSAL, MeshMessages.encode(MeshMessage.Settlement(receipt.toJson())))
                tryFinalizeSettlement(contractId)
            }
            return try {
                withTimeout(30_000) { waiter.await() }
            } catch (e: TimeoutCancellationException) {
                null
            } catch (e: TransferAborted) {
                null
            }
        }

        private suspend fun handleSettlement(m: MeshMessage.Settlement) {
            val res = result ?: return
            val receipt = when (val v = SettlementReceipt.verify(m.receipt, res.remoteIdentityPublicKey, res.handshakeHash)) {
                is CryptoResult.Ok -> v.value
                is CryptoResult.Err -> return violationLocked(TeardownReason.ATTESTATION_INVALID, v.error.message ?: "bad settlement")
            }
            val st = state
            if (st !is LifecycleState.TaskExecuting || st.contractId != receipt.contractId) {
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "settlement for a contract that is not executing")
            }
            if (peerReceipts.putIfAbsent(receipt.contractId, receipt) != null) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "duplicate settlement")
            tryFinalizeSettlement(receipt.contractId)
        }

        private suspend fun tryFinalizeSettlement(contractId: String) {
            val mine = localReceipts[contractId] ?: return
            val theirs = peerReceipts[contractId] ?: return
            if (mine.merkleRootB64 != theirs.merkleRootB64 || mine.bytesTransferred != theirs.bytesTransferred) {
                return violationLocked(TeardownReason.ATTESTATION_INVALID, "settlement receipts disagree")
            }
            val hashes = listOf(mine.receiptHash(), theirs.receiptHash()).sortedBy { it.toHex() }
            val combined = CryptoEngine.sha256(hashes[0], hashes[1]).toHex()
            apply(LifecycleEvent.SettlementSigned(contractId, combined))
            if (tornDown.get()) return
            markContract(contractId, ContractStatus.SETTLED)
            _events.tryEmit(MeshEvent.SettlementCompleted(peerId, contractId, combined))
            settled.getOrPut(contractId) { CompletableDeferred() }.complete(combined)
        }

        private fun markContract(contractId: String, status: ContractStatus) {
            contracts.computeIfPresent(contractId) { _, c -> c.copy(status = status) }
        }

        // ------------------------------------------------------------------ inbound transfer

        private suspend fun handleOffer(m: MeshMessage.TransferOffer) {
            val res = result ?: return
            val st = state
            fun refuse(reason: String) = MeshMessages.encode(MeshMessage.TransferAccept(m.transferId, false, reason))
            if (st !is LifecycleState.TaskExecuting || st.contractId != m.contractId) {
                return sendEncrypted(FrameType.AGENT_PROPOSAL, refuse("not_executing"))
            }
            val c = contracts[m.contractId] ?: return sendEncrypted(FrameType.AGENT_PROPOSAL, refuse("unknown_contract"))
            if (!c.localReceives) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "peer offered data on a contract where we send")
            if (inbound.isNotEmpty()) return sendEncrypted(FrameType.AGENT_PROPOSAL, refuse("busy"))
            val token = CapabilityToken.decode(m.token) ?: return violationLocked(TeardownReason.POLICY_VIOLATION, "malformed capability token")
            val root = macaroonRoot ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "no macaroon root")
            val verdict = token.verify(
                root,
                CapabilityRequest(
                    sessionId = sessionId.toString(), audienceFingerprint = res.remoteFingerprint, contractId = m.contractId,
                    operation = "push", nowSeconds = nowSeconds(), bytes = m.totalBytes, cpuMillis = 0, path = "inbox/${m.contractId}",
                ),
            )
            if (verdict is TokenVerdict.Denied) return violationLocked(TeardownReason.POLICY_VIOLATION, "capability token denied: ${verdict.reason}")
            if (m.totalBytes > c.terms.maxBytes) return violationLocked(TeardownReason.POLICY_VIOLATION, "offer exceeds contract bytes")
            val expectedCount = ((m.totalBytes + m.chunkSize - 1) / m.chunkSize)
            if (expectedCount != m.chunkCount.toLong()) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "chunk count inconsistent with size")
            val file = when (val r = sandbox.openInbound(m.contractId, m.transferId.toHex(), m.totalBytes)) {
                is SandboxResult.Ok -> r.value
                is SandboxResult.Denied -> return sendEncrypted(FrameType.AGENT_PROPOSAL, refuse("sandbox_denied"))
            }
            inbound[m.transferId.toHex()] = InboundTransfer(m, file)
            markContract(m.contractId, ContractStatus.EXECUTING)
            sendEncrypted(FrameType.AGENT_PROPOSAL, MeshMessages.encode(MeshMessage.TransferAccept(m.transferId, true, "ok")))
            log(LogChannel.PROTOCOL, "accepted transfer ${m.transferId.toHex().take(8)}… (${m.totalBytes} bytes, ${m.chunkCount} chunks)")
        }

        private suspend fun handleChunk(b: ChunkBody) {
            val key = b.transferId.toHex()
            val t = inbound[key] ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "chunk for unknown transfer")
            val o = t.offer
            fun nack(code: Byte) = AckBody.ChunkNack(b.transferId, b.chunkIndex, code).encode()
            if (b.chunkCount != o.chunkCount || b.chunkIndex != t.nextExpected) {
                sendEncrypted(FrameType.HEARTBEAT_ACK, nack(1))
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "out-of-order chunk ${b.chunkIndex}, expected ${t.nextExpected}")
            }
            val expectedLen = if (b.chunkIndex == o.chunkCount - 1) (o.totalBytes - b.chunkIndex.toLong() * o.chunkSize).toInt() else o.chunkSize
            if (b.data.size != expectedLen) {
                sendEncrypted(FrameType.HEARTBEAT_ACK, nack(2))
                return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "chunk length ${b.data.size} expected $expectedLen")
            }
            when (val v = MerkleVerifier.verifyChunk(o.merkleRoot, o.chunkCount, b.chunkIndex, b.data, b.proof)) {
                MerkleVerdict.Valid -> Unit
                is MerkleVerdict.Invalid -> {
                    sendEncrypted(FrameType.HEARTBEAT_ACK, nack(3))
                    return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "Merkle proof failed for chunk ${b.chunkIndex}: ${v.reason}")
                }
            }
            try {
                withContext(kotlinx.coroutines.Dispatchers.IO) { t.file.append(b.data) }
            } catch (e: java.io.IOException) {
                sendEncrypted(FrameType.HEARTBEAT_ACK, nack(4))
                return violationLocked(TeardownReason.POLICY_VIOLATION, "write failed: ${e.message}")
            }
            t.nextExpected++
            sendEncrypted(FrameType.HEARTBEAT_ACK, AckBody.ChunkAck(b.transferId, t.nextExpected).encode(), bulk = true)
            if (t.nextExpected % 16 == 0 || t.nextExpected == o.chunkCount) {
                _events.tryEmit(MeshEvent.TransferProgress(peerId, o.contractId, key, t.file.bytesWritten, o.totalBytes, inbound = true))
            }
            if (t.nextExpected == o.chunkCount) {
                inbound.remove(key)
                val ok = withContext(kotlinx.coroutines.Dispatchers.IO) { t.file.commit(o.sha256) }
                sendEncrypted(FrameType.AGENT_PROPOSAL, MeshMessages.encode(MeshMessage.TransferComplete(b.transferId, ok)))
                if (!ok) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "assembled file failed SHA-256 verification")
                _events.tryEmit(MeshEvent.TransferCompleted(peerId, o.contractId, key, t.file.relativeFinalPath, inbound = true, merkleRootHex = o.merkleRoot.toHex()))
                // Receipt issued without holding the lock across the await (we are inside the lock here).
                val res = result ?: return
                val receipt = SettlementReceipt.issue(identity, o.contractId, res.handshakeHash, o.totalBytes, o.merkleRoot, o.sha256, "fulfilled", nowSeconds())
                localReceipts[o.contractId] = receipt
                settled.getOrPut(o.contractId) { CompletableDeferred() }
                sendEncrypted(FrameType.AGENT_PROPOSAL, MeshMessages.encode(MeshMessage.Settlement(receipt.toJson())))
                tryFinalizeSettlement(o.contractId)
            }
        }

        private suspend fun handleAck(a: AckBody) {
            when (a) {
                is AckBody.Heartbeat -> Unit
                is AckBody.ChunkAck -> {
                    val t = outbound[a.transferId.toHex()] ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "ack for unknown transfer")
                    if (a.nextExpected < t.ackedThrough || a.nextExpected > t.chunkCount) {
                        return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "ack out of range")
                    }
                    t.ackedThrough = a.nextExpected
                    t.bump()
                }
                is AckBody.ChunkNack -> {
                    val t = outbound[a.transferId.toHex()] ?: return
                    t.nack = a
                    t.bump()
                }
            }
        }

        private suspend fun handleMessage(msg: MeshMessage) {
            when (msg) {
                is MeshMessage.UwbParams -> handleUwbParams(msg)
                is MeshMessage.UwbResult -> handleUwbResult(msg)
                is MeshMessage.ContractProposal -> handleProposal(msg)
                is MeshMessage.ContractResponse -> handleResponse(msg)
                is MeshMessage.TransferOffer -> handleOffer(msg)
                is MeshMessage.TransferAccept -> {
                    val t = outbound[msg.transferId.toHex()] ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "accept for unknown transfer")
                    if (!t.accepted.complete(msg)) violationLocked(TeardownReason.PROTOCOL_VIOLATION, "duplicate transfer accept")
                }
                is MeshMessage.TransferComplete -> {
                    val t = outbound[msg.transferId.toHex()] ?: return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "completion for unknown transfer")
                    if (t.ackedThrough != t.chunkCount && msg.verified) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "completion before all chunks acked")
                    t.completed.complete(msg)
                }
                is MeshMessage.Settlement -> handleSettlement(msg)
            }
        }

        // ------------------------------------------------------------------ sending

        private suspend fun sendEncrypted(type: FrameType, plaintext: ByteArray, bulk: Boolean = false) {
            val res = result ?: throw IllegalStateException("no transport keys")
            val bytes = sendLock.withLock {
                val seq = res.sendCipher.reserveSequence()
                val header = FrameHeader(WireConstants.PROTOCOL_VERSION, type, sessionId!!, seq, plaintext.size)
                val aad = codec.encodeHeader(header)
                val sealed = res.sendCipher.seal(seq, aad, plaintext)
                val ct = sealed.copyOfRange(0, plaintext.size)
                val tag = sealed.copyOfRange(plaintext.size, sealed.size)
                codec.encode(WireFrame(header, ct, tag))
            }
            rawSend(bytes, bulk)
        }

        private suspend fun rawSend(frame: ByteArray, bulk: Boolean) {
            val link = if (bulk) bulkLink ?: primaryLink else (bulkLink ?: primaryLink)
            try {
                link.send(frame)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (!tornDown.get()) {
                    scope.launch { teardown(TeardownReason.LINK_LOST, "send failed: ${e.message}", notifyPeer = false) }
                }
            }
        }

        // ------------------------------------------------------------------ watchdog

        private suspend fun watchdog() {
            while (scope.isActive && !tornDown.get()) {
                delay(1_000)
                val now = clock()
                lock.withLock {
                    if (tornDown.get()) return
                    val st = state
                    if (SessionLifecycle.isExpired(st, now)) {
                        return violationLocked(TeardownReason.TIMEOUT, "state ${st.phase} exceeded its time budget")
                    }
                    if (now - lastRxMillis > policy.linkTimeoutMillis) {
                        return violationLocked(TeardownReason.LINK_LOST, "no frames for ${policy.linkTimeoutMillis}ms")
                    }
                    val res = result ?: return@withLock
                    if (now - lastHeartbeatMillis >= policy.heartbeatIntervalMillis) {
                        lastHeartbeatMillis = now
                        sendEncrypted(FrameType.HEARTBEAT_ACK, AckBody.Heartbeat(now).encode())
                    }
                    val afterBound = boundDistance != null && boundDistance!! >= 0 && rangingConfig != null &&
                        !(st is LifecycleState.NoiseHandshake && st.subPhase == HandshakeSubPhase.DISTANCE_BOUNDING)
                    if (afterBound) {
                        val fixAge = lastFix?.let { now - it.atMillis } ?: Long.MAX_VALUE
                        if (fixAge > policy.rangingDropoutMillis) {
                            return violationLocked(TeardownReason.RANGING_LOST, "no UWB fix for ${fixAge}ms")
                        }
                    }
                    // Re-attest before our manifest expires so the peer's airlock never sees a stale one.
                    val sentAt = localManifestSentAtSeconds
                    if (sentAt != null && st.phase != LifecyclePhase.NOISE_HANDSHAKE &&
                        now / 1000 - sentAt > localManifestLifetime - 60
                    ) {
                        sendLocalManifest()
                    }
                    // Expire stale proposals.
                    contracts.values.filter { it.peerId == peerId && it.status == ContractStatus.PROPOSED && now / 1000 >= it.expiresAtSeconds }
                        .forEach { c ->
                            contracts[c.contractId] = c.copy(status = ContractStatus.EXPIRED)
                            val cur = state
                            if (cur is LifecycleState.AgentNegotiating && c.contractId in cur.openContractIds) {
                                apply(LifecycleEvent.ContractDeclined(c.contractId))
                            }
                        }
                    if (res.sendCipher.isWiped) return violationLocked(TeardownReason.PROTOCOL_VIOLATION, "transport key wiped")
                }
                publishSnapshots()
            }
        }

        // ------------------------------------------------------------------ state + teardown

        /** Initial, never-failing transitions performed before any coroutine runs. */
        private fun applyInitial(event: LifecycleEvent) {
            val tr = SessionLifecycle.transition(state, event, clock())
            check(tr !is Transition.Violation) { "initial transition rejected" }
            state = tr.next
            _events.tryEmit(MeshEvent.StateChanged(peerId, state))
        }

        /**
         * Applies an FSM event. Must be called with [lock] held. An illegal event (or a
         * violation event) synchronously performs the cryptographic teardown, so callers can
         * rely on [tornDown] immediately afterwards.
         */
        private suspend fun apply(event: LifecycleEvent) {
            if (tornDown.get()) return
            val tr = SessionLifecycle.transition(state, event, clock())
            val prev = state
            if (tr is Transition.Violation) log(LogChannel.PROTOCOL, "FSM violation: ${tr.next.detail}")
            val next = tr.next
            if (next is LifecycleState.Teardown) {
                teardownLocked(next.reason, next.detail, notifyPeer = true)
                return
            }
            state = next
            if (prev != state) _events.tryEmit(MeshEvent.StateChanged(peerId, state))
            if (next is LifecycleState.TaskExecuting && prev !is LifecycleState.TaskExecuting) supersedeOthers(next.contractId)
            publishSnapshots()
        }

        /** Entering TASK_EXECUTING drops every other open contract with this peer. */
        private suspend fun supersedeOthers(acceptedId: String) {
            contracts.values.filter { it.peerId == peerId && it.contractId != acceptedId && it.status in setOf(ContractStatus.PROPOSED, ContractStatus.AWAITING_USER_APPROVAL) }
                .forEach { c ->
                    contracts[c.contractId] = c.copy(status = ContractStatus.EXPIRED)
                    if (c.origin == ContractOrigin.REMOTE) {
                        sendEncrypted(FrameType.AGENT_PROPOSAL, MeshMessages.encode(MeshMessage.ContractResponse(c.contractId, ContractDecision.REJECT, "superseded", null)))
                    }
                }
            _approvals.value = _approvals.value.filterNot { a -> a.peerId == peerId && a.contractId != acceptedId }
        }

        private suspend fun violationLocked(reason: TeardownReason, detail: String) {
            teardownLocked(reason, detail, notifyPeer = true)
        }

        suspend fun teardown(reason: TeardownReason, detail: String, notifyPeer: Boolean) {
            lock.withLock { teardownLocked(reason, detail, notifyPeer) }
        }

        /** Must be called with [lock] held. Idempotent. */
        private suspend fun teardownLocked(reason: TeardownReason, detail: String, notifyPeer: Boolean) {
            if (!tornDown.compareAndSet(false, true)) return
            withContext(NonCancellable) {
                if (state !is LifecycleState.Teardown) {
                    state = LifecycleState.Teardown(reason, state.phase, detail)
                    _events.tryEmit(MeshEvent.StateChanged(peerId, state))
                }
                if (reason !in setOf(TeardownReason.LOCAL_REQUEST, TeardownReason.LINK_LOST)) {
                    _events.tryEmit(MeshEvent.SecurityAlert(peerId, reason, detail))
                }
                log(LogChannel.CRYPTO, "TEARDOWN ($reason): $detail — zeroizing session keys")
                if (notifyPeer && reason != TeardownReason.PEER_ABORT) sendAbortBestEffort(reason)

                jobs.forEach { it.cancel() }
                prepared?.let { p -> try { p.close() } catch (_: Exception) {} }
                prepared = null
                rangingConfig?.wipe()
                rangingConfig = null
                inbound.values.forEach { it.file.abort() }
                inbound.clear()
                outbound.values.forEach { t ->
                    t.accepted.completeExceptionally(TransferAborted(detail))
                    t.completed.completeExceptionally(TransferAborted(detail))
                    t.aborted = true
                    t.bump()
                }
                outbound.clear()
                settled.values.forEach { it.completeExceptionally(TransferAborted(detail)) }
                handshake?.close()
                handshake = null
                result?.close()
                macaroonRoot?.close()
                macaroonRoot = null
                contracts.values.filter { it.peerId == peerId && it.status !in setOf(ContractStatus.SETTLED, ContractStatus.REJECTED, ContractStatus.EXPIRED) }
                    .forEach { contracts[it.contractId] = it.copy(status = ContractStatus.FAILED) }
                _approvals.value = _approvals.value.filterNot { it.peerId == peerId }
                attested.complete(state)
                try { primaryLink.close() } catch (_: Exception) {}
                bulkLink?.let { try { it.close() } catch (_: Exception) {} }
                bulkLink = null
                publishSnapshots()
            }
            // Keep the torn-down snapshot visible briefly, then forget the session so the peer can reconnect.
            scope.launch {
                delay(10_000)
                sessions.remove(peerId, this@PeerSession)
                publishSnapshots()
            }
        }

        private suspend fun sendAbortBestEffort(reason: TeardownReason) {
            val code = when (reason) {
                TeardownReason.AUTHENTICATION_FAILED -> AbortCode.AUTHENTICATION_FAILED
                TeardownReason.REPLAY_DETECTED -> AbortCode.REPLAY_DETECTED
                TeardownReason.DISTANCE_BOUND_EXCEEDED -> AbortCode.DISTANCE_BOUND_EXCEEDED
                TeardownReason.RANGING_LOST -> AbortCode.RANGING_LOST
                TeardownReason.ATTESTATION_INVALID -> AbortCode.ATTESTATION_INVALID
                TeardownReason.POLICY_VIOLATION, TeardownReason.AGENT_SCHEMA_VIOLATION -> AbortCode.POLICY_VIOLATION
                TeardownReason.PROTOCOL_VIOLATION -> AbortCode.PROTOCOL_VIOLATION
                TeardownReason.TIMEOUT -> AbortCode.TIMEOUT
                TeardownReason.LOCAL_REQUEST -> AbortCode.USER_TERMINATED
                else -> AbortCode.UNSPECIFIED
            }
            val sid = sessionId ?: return
            try {
                val res = result
                val frame = if (res != null && !res.sendCipher.isWiped) {
                    val seq = res.sendCipher.reserveSequence()
                    val header = FrameHeader(WireConstants.PROTOCOL_VERSION, FrameType.SECURITY_ABORT, sid, seq, 1)
                    val sealed = res.sendCipher.seal(seq, codec.encodeHeader(header), byteArrayOf(code.code))
                    WireFrame(header, sealed.copyOfRange(0, 1), sealed.copyOfRange(1, sealed.size))
                } else {
                    val tag = ByteArray(16).also { it[0] = code.code }
                    WireFrame(FrameHeader(WireConstants.PROTOCOL_VERSION, FrameType.SECURITY_ABORT, sid, 0, 0), ByteArray(0), tag)
                }
                withTimeout(1_500) { primaryLink.send(codec.encode(frame)) }
            } catch (_: Exception) {
                // Best effort: the link may already be gone.
            }
        }

        // ------------------------------------------------------------------ views

        fun attestation(): SessionAttestation {
            val st = state
            return SessionAttestation(
                peerId = peerId,
                phase = st.phase,
                handshakeComplete = result != null,
                transportKeysLive = result?.let { !it.sendCipher.isWiped && !it.receiveCipher.isWiped } ?: false,
                peerFingerprint = if (st is LifecycleState.Teardown) null else result?.remoteFingerprint,
                manifestExpiresAtSeconds = peerManifest?.expiresAtSeconds,
                distanceBound = boundDistance != null && boundDistance!! >= 0,
                boundDistanceMeters = boundDistance,
                lastFixAgeMillis = lastFix?.let { clock() - it.atMillis },
                lastDistanceMeters = lastFix?.distanceMeters,
                executingContractId = (st as? LifecycleState.TaskExecuting)?.contractId,
            )
        }

        fun snapshot(): PeerSnapshot {
            val st = state
            return PeerSnapshot(
                peerId = peerId, endpointId = endpointId, beaconToken = beaconToken, state = st, role = role,
                peerFingerprint = result?.remoteFingerprint ?: peerManifest?.issuerFingerprint,
                identityHardwareBacked = null,
                boundDistanceMeters = boundDistance, lastFix = lastFix, provisionedSts = provisionedSts,
                manifestExpiresAtSeconds = peerManifest?.expiresAtSeconds, bulkLinkActive = bulkLink != null,
                openContracts = contracts.values.filter { it.peerId == peerId && it.status in setOf(ContractStatus.PROPOSED, ContractStatus.ACCEPTED, ContractStatus.EXECUTING, ContractStatus.AWAITING_USER_APPROVAL) }.map { it.contractId },
            )
        }

        private fun log(channel: LogChannel, text: String) {
            _events.tryEmit(MeshEvent.Log(peerId, channel, text))
        }
    }
}

class TransferAborted(message: String) : Exception(message)
