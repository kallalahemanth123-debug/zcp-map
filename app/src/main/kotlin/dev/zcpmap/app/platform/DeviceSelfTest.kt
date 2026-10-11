package dev.zcpmap.app.platform

import android.Manifest
import android.app.ActivityManager
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.aware.WifiAwareManager
import android.os.StatFs
import android.provider.Settings
import androidx.core.content.ContextCompat
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import dev.zcpmap.agent.LocalNetworkPolicy
import dev.zcpmap.agent.OpenAiCompatibleBackend
import dev.zcpmap.app.di.NodeGraph
import dev.zcpmap.app.settings.AgentMode
import dev.zcpmap.app.settings.AgentSettings
import dev.zcpmap.security.CryptoEngine
import dev.zcpmap.transport.UwbProximityManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI

enum class CheckLevel { PASS, WARN, FAIL }

data class SelfCheck(val name: String, val level: CheckLevel, val detail: String, val fix: String? = null)

/**
 * Everything that can stop two phones from working together, checked on the real device in a few
 * seconds. Run it on both phones before the first session (SELF-TEST button).
 */
object DeviceSelfTest {

    val REQUIRED_PERMISSIONS = listOf(
        Manifest.permission.UWB_RANGING,
        Manifest.permission.NEARBY_WIFI_DEVICES,
        Manifest.permission.BLUETOOTH_ADVERTISE,
        Manifest.permission.BLUETOOTH_CONNECT,
        Manifest.permission.BLUETOOTH_SCAN,
        Manifest.permission.ACCESS_FINE_LOCATION,
    )

    suspend fun run(context: Context, graph: NodeGraph?, settings: AgentSettings): List<SelfCheck> = withContext(Dispatchers.IO) {
        val out = ArrayList<SelfCheck>()
        val pm = context.packageManager

        val missing = REQUIRED_PERMISSIONS.filter { ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED }
        out += if (missing.isEmpty()) SelfCheck("Permissions", CheckLevel.PASS, "all ${REQUIRED_PERMISSIONS.size} granted")
        else SelfCheck("Permissions", CheckLevel.FAIL, "missing: " + missing.joinToString { it.substringAfterLast('.') }, "Settings → Apps → ZCP-MAP → Permissions → allow Nearby devices and Location")

        val bt = context.getSystemService(BluetoothManager::class.java)?.adapter
        out += when {
            bt == null -> SelfCheck("Bluetooth", CheckLevel.FAIL, "no Bluetooth adapter")
            !bt.isEnabled -> SelfCheck("Bluetooth", CheckLevel.FAIL, "Bluetooth is off", "Turn Bluetooth on")
            else -> SelfCheck("Bluetooth", CheckLevel.PASS, "on")
        }

        val loc = context.getSystemService(LocationManager::class.java)
        out += if (loc?.isLocationEnabled == true) SelfCheck("Location services", CheckLevel.PASS, "on")
        else SelfCheck("Location services", CheckLevel.WARN, "off — Nearby discovery fails on some phones without it", "Turn Location on (no position is ever used)")

        val gms = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context)
        out += if (gms == ConnectionResult.SUCCESS) SelfCheck("Google Play services", CheckLevel.PASS, "available (needed for Nearby Connections)")
        else SelfCheck("Google Play services", CheckLevel.FAIL, "status $gms", "Install or update Google Play services")

        val uwb = UwbProximityManager(context).probe()
        out += when {
            !uwb.hardware -> SelfCheck("UWB radio", CheckLevel.FAIL, uwb.detail, "This phone cannot do distance bounding. Use two UWB phones (e.g. Pixel 6 Pro or newer Pro models).")
            !uwb.enabled -> SelfCheck("UWB radio", CheckLevel.FAIL, uwb.detail, "Settings → Connected devices → Connection preferences → Ultra-Wideband: on")
            else -> SelfCheck("UWB radio", CheckLevel.PASS, "on; angle-of-arrival ${if (uwb.angleOfArrival) "yes" else "no"}; ${uwb.detail}")
        }
        if (uwb.enabled) {
            out += when {
                uwb.provisionedSts -> SelfCheck("Secure ranging (provisioned STS)", CheckLevel.PASS, "supported — relay-resistant distance bounding")
                settings.requireProvisionedSts -> SelfCheck("Secure ranging (provisioned STS)", CheckLevel.FAIL,
                    "not supported by this phone's UWB stack, and SETUP requires it — every handshake will be refused",
                    "SETUP → turn off 'Require provisioned STS' (weaker: no protection against relay attacks)")
                else -> SelfCheck("Secure ranging (provisioned STS)", CheckLevel.WARN, "not supported; using static STS (no relay protection)")
            }
        }

        val awareFeature = pm.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)
        val aware = context.getSystemService(WifiAwareManager::class.java)
        out += when {
            !awareFeature -> SelfCheck("Wi-Fi Aware", CheckLevel.WARN, "not on this phone — transfers use Nearby only (slower)")
            aware?.isAvailable != true -> SelfCheck("Wi-Fi Aware", CheckLevel.WARN, "unavailable right now (Wi-Fi off or hotspot on) — Nearby is used", "Turn Wi-Fi on, hotspot off")
            else -> SelfCheck("Wi-Fi Aware", CheckLevel.PASS, "available for fast transfers")
        }

        if (graph != null) {
            val id = graph.identity
            val probe = CryptoEngine.randomBytes(32)
            val ok = try { CryptoEngine.ed25519Verify(id.publicKey, probe, id.sign(probe)) } catch (e: Exception) { false }
            out += when {
                !ok -> SelfCheck("Identity key", CheckLevel.FAIL, "signing self-test failed (${id.securityLevel.label})", "Unlock the phone and run the self-test again")
                id.securityLevel.hardwareBacked -> SelfCheck("Identity key", CheckLevel.PASS, id.securityLevel.label)
                else -> SelfCheck("Identity key", CheckLevel.WARN, "${id.securityLevel.label} — this device has no secure key hardware")
            }
        } else {
            out += SelfCheck("Identity key", CheckLevel.FAIL, "node not started", "Restart the app")
        }

        val autoTime = try { Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME) == 1 } catch (e: Settings.SettingNotFoundException) { false }
        out += if (autoTime) SelfCheck("Clock", CheckLevel.PASS, "automatic time on")
        else SelfCheck("Clock", CheckLevel.WARN, "automatic time is off — phones more than ~60 s apart refuse each other", "Settings → System → Date & time → Set time automatically")

        val free = try { StatFs(context.noBackupFilesDir.path).availableBytes } catch (e: IllegalArgumentException) { 0L }
        out += if (free >= 2L shl 30) SelfCheck("Free storage", CheckLevel.PASS, "${free shr 30} GiB")
        else SelfCheck("Free storage", CheckLevel.WARN, "${free shr 20} MiB — incoming transfers need room (1 GiB is always kept free)")

        out += agentCheck(context, settings)
        out
    }

    private fun agentCheck(context: Context, s: AgentSettings): SelfCheck = when (s.mode) {
        AgentMode.RULES -> SelfCheck("Agent", CheckLevel.PASS, "rule-based — no model or server needed")
        AgentMode.OWN_SERVER -> serverCheck(s)
        AgentMode.ON_DEVICE -> {
            val f = s.modelFileName?.let { File(modelDir(context), it) }
            val ram = (context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager).let { am ->
                ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }.totalMem
            }
            when {
                f == null || !f.isFile -> SelfCheck("Agent", CheckLevel.FAIL, "no on-device model imported", "SETUP → Import model (.litertlm)")
                ram < (6L shl 30) -> SelfCheck("Agent", CheckLevel.WARN, "model ${f.name} (${f.length() shr 20} MiB); phone has ${ram shr 30} GiB RAM — use a 1B model")
                else -> SelfCheck("Agent", CheckLevel.PASS, "model ${f.name} (${f.length() shr 20} MiB) ready")
            }
        }
    }

    private fun serverCheck(s: AgentSettings): SelfCheck {
        val url = OpenAiCompatibleBackend.chatCompletionsUrl(s.serverUrl)
        when (val v = LocalNetworkPolicy.checkResolved(url)) {
            is LocalNetworkPolicy.Verdict.Refused -> return SelfCheck("Agent server", CheckLevel.FAIL, v.reason, "SETUP → use your server's local address or https://")
            LocalNetworkPolicy.Verdict.Allowed -> Unit
        }
        val uri = URI(url)
        val port = if (uri.port > 0) uri.port else if (uri.scheme == "https") 443 else 80
        return try {
            Socket().use { it.connect(InetSocketAddress(uri.host, port), 2_000) }
            SelfCheck("Agent server", CheckLevel.PASS, "${uri.host}:$port reachable; model '${s.serverModel}'")
        } catch (e: Exception) {
            SelfCheck("Agent server", CheckLevel.FAIL, "cannot reach ${uri.host}:$port (${e.javaClass.simpleName})",
                "Same Wi-Fi as the server? Ollama: start it with OLLAMA_HOST=0.0.0.0 so other devices can connect")
        }
    }

    fun modelDir(context: Context): File = File(context.noBackupFilesDir, "models").apply { mkdirs() }
}
