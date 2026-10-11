package dev.zcpmap.transport

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import androidx.core.uwb.RangingParameters
import androidx.core.uwb.RangingResult
import androidx.core.uwb.UwbAddress
import androidx.core.uwb.UwbClientSessionScope
import androidx.core.uwb.UwbComplexChannel
import androidx.core.uwb.UwbControllerSessionScope
import androidx.core.uwb.UwbDevice
import androidx.core.uwb.UwbManager
import dev.zcpmap.mesh.BoundRangingConfig
import dev.zcpmap.mesh.PreparedRanging
import dev.zcpmap.mesh.RangingEvent
import dev.zcpmap.mesh.SecureRangingPort
import dev.zcpmap.mesh.UwbLocalParams
import dev.zcpmap.protocol.HandshakeRole
import dev.zcpmap.security.CryptoEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.onCompletion

/*
 * UWB secure ranging through androidx.core.uwb (1.0.0).
 *
 * Role mapping: the Noise initiator is the UWB controller and assigns the complex channel; the
 * responder is the controlee. Out-of-band parameters (addresses, channel, capabilities) are carried
 * in encrypted UWB_BIND frames by the mesh coordinator, never in the clear.
 *
 * Cryptographic binding: the 16-byte provisioned-STS session key and the 32-bit session id are both
 * derived from the Noise exporter (a secret only the two authenticated endpoints share) with the
 * handshake transcript hash as HKDF salt. The radios therefore only produce valid scrambled timestamp
 * sequences for each other; a relay that forwards packets adds time of flight (rejected by the distance
 * bound) and cannot synthesize an earlier-arriving STS without the key.
 *
 * Static STS (8-byte vendor id + static IV) is NOT cryptographically secure ranging; it is used only if
 * the coordinator's policy explicitly allows it, with the IV derived from the same secret.
 */
data class UwbProbe(
    val hardware: Boolean,
    val enabled: Boolean,
    /** Key-derived (provisioned) STS — required for cryptographic distance bounding. */
    val provisionedSts: Boolean,
    val angleOfArrival: Boolean,
    val detail: String,
)

class UwbProximityManager(private val context: Context) : SecureRangingPort {
    private val manager: UwbManager by lazy { UwbManager.createInstance(context) }

    override val isAvailable: Boolean
        get() = context.packageManager.hasSystemFeature(PackageManager.FEATURE_UWB)

    /** What this phone's UWB stack supports; used by the in-app self-test. Never throws. */
    suspend fun probe(): UwbProbe {
        if (!isAvailable) return UwbProbe(false, false, false, false, "this phone has no UWB radio")
        return try {
            if (!manager.isAvailable()) return UwbProbe(true, false, false, false, "UWB is off (Settings → Connected devices → UWB) or blocked in this country / airplane mode")
            val caps = manager.controllerSessionScope().rangingCapabilities
            val psts = caps.supportedConfigIds.contains(RangingParameters.CONFIG_PROVISIONED_UNICAST_DS_TWR)
            UwbProbe(true, true, psts, caps.isAzimuthalAngleSupported,
                "config ids ${caps.supportedConfigIds.sorted()}, channels ${caps.supportedChannels.sorted()}")
        } catch (e: SecurityException) {
            UwbProbe(true, false, false, false, "UWB_RANGING permission not granted")
        } catch (e: Exception) {
            UwbProbe(true, false, false, false, "UWB service error: ${e.javaClass.simpleName} ${e.message ?: ""}".trim())
        }
    }

    override suspend fun prepare(role: HandshakeRole): PreparedRanging {
        check(isAvailable) { "device has no UWB radio" }
        check(manager.isAvailable()) { "UWB is turned off or restricted (airplane mode / country code)" }
        val scope: UwbClientSessionScope = if (role == HandshakeRole.INITIATOR) {
            manager.controllerSessionScope()
        } else {
            manager.controleeSessionScope()
        }
        val caps = scope.rangingCapabilities
        val provisioned = caps.supportedConfigIds.contains(RangingParameters.CONFIG_PROVISIONED_UNICAST_DS_TWR)
        val channel = (scope as? UwbControllerSessionScope)?.uwbComplexChannel
        val local = UwbLocalParams(
            address = scope.localAddress.address,
            channel = channel?.channel,
            preambleIndex = channel?.preambleIndex,
            supportsProvisionedSts = provisioned,
            supportsAngleOfArrival = caps.isAzimuthalAngleSupported,
        )
        Log.i(TAG, "UWB scope ready role=$role psts=$provisioned aoa=${caps.isAzimuthalAngleSupported} ch=${channel?.channel}")
        return AndroidPreparedRanging(scope, local)
    }

    private class AndroidPreparedRanging(
        private val scope: UwbClientSessionScope,
        override val local: UwbLocalParams,
    ) : PreparedRanging {

        override fun start(config: BoundRangingConfig): Flow<RangingEvent> {
            val key = config.stsKey()
            val sessionKeyInfo = if (config.provisionedSts) {
                key.copyOf()
            } else {
                // Static STS: 2-byte vendor id (0x5A43, "ZC") + 6-byte static STS IV from the secret key.
                byteArrayOf(0x5A, 0x43) + CryptoEngine.sha256("ZCP1-STATIC-STS".toByteArray(), key).copyOf(6)
            }
            java.util.Arrays.fill(key, 0)
            val params = RangingParameters(
                uwbConfigType = if (config.provisionedSts) RangingParameters.CONFIG_PROVISIONED_UNICAST_DS_TWR
                else RangingParameters.CONFIG_UNICAST_DS_TWR,
                sessionId = config.sessionId,
                subSessionId = 0,
                sessionKeyInfo = sessionKeyInfo,
                subSessionKeyInfo = null,
                complexChannel = UwbComplexChannel(config.channel, config.preambleIndex),
                peerDevices = listOf(UwbDevice(UwbAddress(config.peerAddress))),
                updateRateType = RangingParameters.RANGING_UPDATE_RATE_FREQUENT,
            )
            return flow {
                try {
                    scope.prepareSession(params)
                        .mapNotNull { r -> translate(r) }
                        .collect { emit(it) }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    emit(RangingEvent.Failure("${e.javaClass.simpleName}: ${e.message}"))
                }
            }.catch { e -> emit(RangingEvent.Failure(e.message ?: "ranging error")) }
                .onCompletion { java.util.Arrays.fill(sessionKeyInfo, 0) }
        }

        private fun translate(r: RangingResult): RangingEvent? = when (r) {
            is RangingResult.RangingResultPosition -> {
                val p = r.position
                RangingEvent.Sample(
                    distanceMeters = p.distance?.value?.toDouble(),
                    azimuthDegrees = p.azimuth?.value?.toDouble(),
                    elevationDegrees = p.elevation?.value?.toDouble(),
                    elapsedRealtimeNanos = p.elapsedRealtimeNanos,
                )
            }
            is RangingResult.RangingResultPeerDisconnected -> RangingEvent.Dropout("peer disconnected")
            is RangingResult.RangingResultFailure -> RangingEvent.Failure("ranging failure")
            else -> null // RangingResultInitialized and future informational results
        }

        override suspend fun close() {
            // androidx.core.uwb stops the session when the prepareSession flow collection is cancelled;
            // the coordinator cancels that collection before calling close().
        }
    }

    companion object {
        private const val TAG = "ZcpUwb"
    }
}
