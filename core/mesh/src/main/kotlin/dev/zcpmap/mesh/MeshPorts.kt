package dev.zcpmap.mesh

import dev.zcpmap.protocol.HandshakeRole
import dev.zcpmap.protocol.LifecycleState
import dev.zcpmap.protocol.TeardownReason
import kotlinx.coroutines.flow.Flow

/*
 * Ports (Clean Architecture boundaries). The mesh domain depends only on these interfaces; the
 * Android transport module implements them with Nearby Connections, Wi-Fi Aware and androidx UWB,
 * and the test suite implements them in memory.
 */

// ------------------------------------------------------------------------------------------
// Link layer
// ------------------------------------------------------------------------------------------

/** A reliable, ordered, message-oriented bidirectional pipe to exactly one peer. */
interface FrameLink {
    val linkId: String
    /** Largest single frame this link can carry (Nearby BYTES: 32 768). */
    val maxFrameBytes: Int
    /** Emits complete frames as received. Completes normally on orderly close, exceptionally on failure. */
    val incoming: Flow<ByteArray>
    suspend fun send(frame: ByteArray)
    suspend fun close()
}

sealed interface DiscoveryEvent {
    /** A peer advertising a ZCP1 beacon was found. [endpointId] is transport-scoped and opaque. */
    data class PeerFound(val endpointId: String, val beaconToken: String) : DiscoveryEvent
    data class PeerLost(val endpointId: String) : DiscoveryEvent
    /** A remote peer opened a link to us; we act as Noise responder. */
    data class InboundLink(val endpointId: String, val beaconToken: String, val link: FrameLink) : DiscoveryEvent
}

/** Parameters for an optional high-bandwidth link keyed from the Noise exporter. */
class BulkLinkParams(
    /** 8-byte match token both peers derive identically; never derivable by outsiders. */
    val matchToken: ByteArray,
    /** Wi-Fi Aware NDP passphrase (base64url of 32 secret bytes, 43 chars). */
    val pskPassphrase: String,
)

interface PeerTransport {
    val discovery: Flow<DiscoveryEvent>
    suspend fun startDiscovery(beaconToken: String)
    suspend fun stopDiscovery()
    /** Opens an outbound link (we are the Noise initiator). */
    suspend fun connect(endpointId: String): FrameLink
    /**
     * Attempts to establish a Wi-Fi Aware data path for bulk frames. Returns null when the
     * hardware is unavailable; callers then keep using the primary link.
     */
    suspend fun openBulkLink(endpointId: String, role: HandshakeRole, params: BulkLinkParams): FrameLink?
}

// ------------------------------------------------------------------------------------------
// Secure ranging
// ------------------------------------------------------------------------------------------

data class UwbLocalParams(
    val address: ByteArray,
    /** Only the controller (Noise initiator) assigns the complex channel. */
    val channel: Int?,
    val preambleIndex: Int?,
    val supportsProvisionedSts: Boolean,
    val supportsAngleOfArrival: Boolean,
) {
    override fun equals(other: Any?) = other is UwbLocalParams && address.contentEquals(other.address) &&
        channel == other.channel && preambleIndex == other.preambleIndex &&
        supportsProvisionedSts == other.supportsProvisionedSts && supportsAngleOfArrival == other.supportsAngleOfArrival
    override fun hashCode() = address.contentHashCode()
}

class BoundRangingConfig(
    /** 32-bit UWB session id derived from the Noise exporter. */
    val sessionId: Int,
    /** 16-byte provisioned-STS session key derived from the Noise exporter (secret). */
    stsKey: ByteArray,
    val peerAddress: ByteArray,
    val channel: Int,
    val preambleIndex: Int,
    val provisionedSts: Boolean,
) {
    private val key = stsKey.copyOf()
    fun stsKey(): ByteArray = key.copyOf()
    fun wipe() = java.util.Arrays.fill(key, 0)
}

sealed interface RangingEvent {
    data class Sample(
        val distanceMeters: Double?,
        val azimuthDegrees: Double?,
        val elevationDegrees: Double?,
        val elapsedRealtimeNanos: Long,
    ) : RangingEvent

    data class Dropout(val reason: String) : RangingEvent
    data class Failure(val reason: String) : RangingEvent
}

interface PreparedRanging {
    val local: UwbLocalParams
    /** Cold flow; collecting starts the secure ranging session, cancelling stops it. */
    fun start(config: BoundRangingConfig): Flow<RangingEvent>
    suspend fun close()
}

interface SecureRangingPort {
    val isAvailable: Boolean
    /** Allocates a session scope (fresh UWB address). Controller == Noise initiator. */
    suspend fun prepare(role: HandshakeRole): PreparedRanging
}

// ------------------------------------------------------------------------------------------
// Device state
// ------------------------------------------------------------------------------------------

enum class ThermalLevel(val wire: String, val severity: Int) {
    NOMINAL("nominal", 0), ELEVATED("elevated", 1), SEVERE("severe", 2), CRITICAL("critical", 3)
}

data class DeviceConstraints(
    val batteryPercent: Int,
    val charging: Boolean,
    val thermal: ThermalLevel,
    val freeStorageBytes: Long,
)

fun interface DeviceConstraintsPort {
    fun current(): DeviceConstraints
}

// ------------------------------------------------------------------------------------------
// Policy
// ------------------------------------------------------------------------------------------

data class MeshPolicy(
    /** Maximum verified physical distance for any session, meters. */
    val maxDistanceMeters: Double = 3.0,
    /** Require provisioned (key-derived) STS. Static STS is not cryptographically secure ranging. */
    val requireProvisionedSts: Boolean = true,
    /** If the device has no UWB, refuse all sessions (true) or allow unbound sessions (false). */
    val requireUwb: Boolean = true,
    val minRangingSamples: Int = 8,
    val rangingWindowMillis: Long = 8_000,
    /** Peer-reported and locally measured distances must agree within this tolerance. */
    val crossCheckToleranceMeters: Double = 0.75,
    /** Continuous enforcement: teardown if no ranging sample arrives for this long. */
    val rangingDropoutMillis: Long = 6_000,
    val maxConcurrentSessions: Int = 4,
    val maxTransferBytes: Long = 512L * 1024 * 1024,
    val maxCpuMillisPerContract: Long = 10 * 60_000,
    val minBatteryPercentForWork: Int = 20,
    val maxThermalForWork: ThermalLevel = ThermalLevel.ELEVATED,
    val storageReserveBytes: Long = 1L shl 30,
    /** Contracts above this many bytes need a human tap in the UI before acceptance. */
    val userApprovalAboveBytes: Long = 64L * 1024 * 1024,
    val chunkSizeBytes: Int = 16 * 1024,
    val sendWindowChunks: Int = 8,
    val heartbeatIntervalMillis: Long = 5_000,
    val linkTimeoutMillis: Long = 20_000,
    val contractTtlSeconds: Long = 300,
) {
    init {
        require(maxDistanceMeters in 0.1..10.0)
        require(chunkSizeBytes in 1024..dev.zcpmap.protocol.ChunkBody.MAX_CHUNK_DATA)
        require(sendWindowChunks in 1..64)
    }
}

// ------------------------------------------------------------------------------------------
// Observable state for UI and agent
// ------------------------------------------------------------------------------------------

data class RadarFix(val distanceMeters: Double, val azimuthDegrees: Double?, val elevationDegrees: Double?, val atMillis: Long)

data class PeerSnapshot(
    val peerId: String,
    val endpointId: String,
    val beaconToken: String,
    val state: LifecycleState,
    val role: HandshakeRole?,
    val peerFingerprint: String?,
    val identityHardwareBacked: Boolean?,
    val boundDistanceMeters: Double?,
    val lastFix: RadarFix?,
    val provisionedSts: Boolean?,
    val manifestExpiresAtSeconds: Long?,
    val bulkLinkActive: Boolean,
    val openContracts: List<String>,
)

sealed interface MeshEvent {
    val peerId: String

    data class PeerDiscovered(override val peerId: String) : MeshEvent
    data class PeerLost(override val peerId: String) : MeshEvent
    data class StateChanged(override val peerId: String, val state: LifecycleState) : MeshEvent
    data class Ranging(override val peerId: String, val fix: RadarFix) : MeshEvent
    data class ContractProposed(override val peerId: String, val contract: ContractRecord) : MeshEvent
    data class ContractAnswered(override val peerId: String, val contractId: String, val decision: ContractDecision, val reason: String?) : MeshEvent
    data class TransferProgress(override val peerId: String, val contractId: String, val transferIdHex: String, val bytesDone: Long, val totalBytes: Long, val inbound: Boolean) : MeshEvent
    data class TransferCompleted(override val peerId: String, val contractId: String, val transferIdHex: String, val path: String, val inbound: Boolean, val merkleRootHex: String) : MeshEvent
    data class SettlementCompleted(override val peerId: String, val contractId: String, val receiptHashHex: String) : MeshEvent
    data class SecurityAlert(override val peerId: String, val reason: TeardownReason, val detail: String) : MeshEvent
    data class ApprovalRequired(override val peerId: String, val approvalId: String, val summary: String) : MeshEvent
    data class Log(override val peerId: String, val channel: LogChannel, val text: String) : MeshEvent
}

enum class LogChannel { TRANSPORT, CRYPTO, RANGING, PROTOCOL, PEER_UNTRUSTED }
