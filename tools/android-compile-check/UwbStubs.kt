// Signatures copied from androidx/androidx androidx-main core/uwb/uwb/src/main/java/androidx/core/uwb (bodies removed).
package androidx.core.uwb
import android.content.Context
import kotlinx.coroutines.flow.Flow
public class UwbAddress(public val address: ByteArray)
public class UwbDevice(public val address: UwbAddress) { public companion object { @JvmStatic public fun createForAddress(address: ByteArray): UwbDevice = TODO() } }
public class UwbComplexChannel(public val channel: Int, public val preambleIndex: Int)
public class UwbRangeDataNtfConfig
public class RangingMeasurement(public val value: Float)
public class RangingPosition(public val distance: RangingMeasurement?, public val azimuth: RangingMeasurement?, public val elevation: RangingMeasurement?, public val elapsedRealtimeNanos: Long)
public class RangingParameters @JvmOverloads constructor(
    public val uwbConfigType: Int, public val sessionId: Int, public val subSessionId: Int,
    public val sessionKeyInfo: ByteArray?, public val subSessionKeyInfo: ByteArray?,
    public val complexChannel: UwbComplexChannel?, public val peerDevices: List<UwbDevice>, public val updateRateType: Int,
    public val uwbRangeDataNtfConfig: UwbRangeDataNtfConfig? = null, public val slotDurationMillis: Long = 2, public val isAoaDisabled: Boolean = false,
) { public companion object {
    public const val CONFIG_UNICAST_DS_TWR: Int = 1
    public const val CONFIG_PROVISIONED_UNICAST_DS_TWR: Int = 4
    public const val RANGING_UPDATE_RATE_AUTOMATIC: Int = 1
    public const val RANGING_UPDATE_RATE_INFREQUENT: Int = 2
    public const val RANGING_UPDATE_RATE_FREQUENT: Int = 3
} }
public interface SensorFusionResult { public val device: UwbDevice }
public sealed class RangingResult : SensorFusionResult {
    public abstract override val device: UwbDevice
    public class RangingResultPosition(override val device: UwbDevice, public val position: RangingPosition) : RangingResult()
    public class RangingResultPeerDisconnected(override val device: UwbDevice, public val reason: Int) : RangingResult()
    public class RangingResultInitialized(override val device: UwbDevice) : RangingResult()
    public class RangingResultFailure(override val device: UwbDevice, public val reason: Int) : RangingResult()
}
public class RangingCapabilities(
    public val isDistanceSupported: Boolean, public val isAzimuthalAngleSupported: Boolean, public val isElevationAngleSupported: Boolean,
    public val minRangingInterval: Int, public val supportedChannels: Set<Int>, public val supportedNtfConfigs: Set<Int>,
    public val supportedConfigIds: Set<Int>, public val supportedSlotDurations: Set<Int>, public val supportedRangingUpdateRates: Set<Int>,
    public val isRangingIntervalReconfigureSupported: Boolean, public val isBackgroundRangingSupported: Boolean,
)
public interface UwbClientSessionScope {
    public fun prepareSession(parameters: RangingParameters): Flow<RangingResult>
    public val rangingCapabilities: RangingCapabilities
    public val localAddress: UwbAddress
}
public interface UwbControllerSessionScope : UwbClientSessionScope {
    public val uwbComplexChannel: UwbComplexChannel
    public suspend fun addControlee(address: UwbAddress)
}
public interface UwbControleeSessionScope : UwbClientSessionScope
public interface UwbManager : AutoCloseable {
    public companion object { @JvmStatic public fun createInstance(context: Context): UwbManager = TODO() }
    public suspend fun controleeSessionScope(): UwbControleeSessionScope
    public suspend fun controllerSessionScope(): UwbControllerSessionScope
    public suspend fun isAvailable(): Boolean
}
