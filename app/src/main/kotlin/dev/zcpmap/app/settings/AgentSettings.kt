package dev.zcpmap.app.settings

import android.content.Context
import dev.zcpmap.agent.LocalNetworkPolicy

/** Which "brain" negotiates for this phone. None of them uses a cloud API. */
enum class AgentMode(val label: String, val manifestId: String) {
    RULES("Rule-based (no AI)", "rule-based"),
    ON_DEVICE("On-device model", "on-device"),
    OWN_SERVER("My own server", "own-server"),
}

data class AgentSettings(
    /** Rule-based by default: works immediately, with no model download and no server. */
    val mode: AgentMode = AgentMode.RULES,
    // --- own server (Ollama, LM Studio, llama.cpp, vLLM) ---
    val serverUrl: String = "",
    val serverModel: String = "",
    val serverNativeTools: Boolean = true,
    // --- on-device (LiteRT-LM) ---
    /** File name inside the app's private model folder, set by the import button. */
    val modelFileName: String? = null,
    val onDeviceNativeTools: Boolean = false,
    val onDeviceGpu: Boolean = false,
    /** Must not exceed the context size the .litertlm file was built for. */
    val onDeviceContextTokens: Int = 4096,
    // --- rule-based ---
    val autoAccept: Boolean = true,
    val maxAcceptMb: Int = 64,
    // --- mesh ---
    val radiusMeters: Double = 3.0,
    /** Off = allow static-STS UWB on phones without provisioned STS (weaker: no relay protection). */
    val requireProvisionedSts: Boolean = true,
) {
    /** Returns a list of problems; empty when the settings can be used. */
    fun validate(): List<String> {
        val errors = ArrayList<String>()
        when (mode) {
            AgentMode.OWN_SERVER -> {
                if (serverUrl.isBlank()) errors += "Enter your server address, e.g. http://192.168.1.20:11434"
                else (LocalNetworkPolicy.checkUrlShape(serverUrl) as? LocalNetworkPolicy.Verdict.Refused)?.let { errors += it.reason }
                if (serverModel.isBlank()) errors += "Enter the model name exactly as your server lists it, e.g. qwen2.5:7b-instruct"
            }
            AgentMode.ON_DEVICE -> {
                if (modelFileName == null) errors += "Import a .litertlm model file first"
                if (onDeviceContextTokens !in 1024..32768) errors += "Context tokens must be between 1024 and 32768"
            }
            AgentMode.RULES -> if (maxAcceptMb !in 1..4096) errors += "Max accepted size must be between 1 and 4096 MB"
        }
        if (radiusMeters !in 0.5..10.0) errors += "Radius must be between 0.5 and 10 m"
        return errors
    }
}

/** Non-secret settings in private SharedPreferences (excluded from backup). The server token lives in the Keystore vault. */
class SettingsStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("zcp_settings", Context.MODE_PRIVATE)

    fun load(): AgentSettings {
        val d = AgentSettings()
        return AgentSettings(
            mode = prefs.getString("mode", null)?.let { n -> AgentMode.entries.firstOrNull { it.name == n } } ?: d.mode,
            serverUrl = prefs.getString("server_url", d.serverUrl) ?: d.serverUrl,
            serverModel = prefs.getString("server_model", d.serverModel) ?: d.serverModel,
            serverNativeTools = prefs.getBoolean("server_native_tools", d.serverNativeTools),
            modelFileName = prefs.getString("model_file", null),
            onDeviceNativeTools = prefs.getBoolean("device_native_tools", d.onDeviceNativeTools),
            onDeviceGpu = prefs.getBoolean("device_gpu", d.onDeviceGpu),
            onDeviceContextTokens = prefs.getInt("device_ctx", d.onDeviceContextTokens),
            autoAccept = prefs.getBoolean("auto_accept", d.autoAccept),
            maxAcceptMb = prefs.getInt("max_accept_mb", d.maxAcceptMb),
            radiusMeters = prefs.getFloat("radius", d.radiusMeters.toFloat()).toDouble(),
            requireProvisionedSts = prefs.getBoolean("require_psts", d.requireProvisionedSts),
        )
    }

    fun save(s: AgentSettings) {
        prefs.edit()
            .putString("mode", s.mode.name)
            .putString("server_url", s.serverUrl.trim())
            .putString("server_model", s.serverModel.trim())
            .putBoolean("server_native_tools", s.serverNativeTools)
            .putString("model_file", s.modelFileName)
            .putBoolean("device_native_tools", s.onDeviceNativeTools)
            .putBoolean("device_gpu", s.onDeviceGpu)
            .putInt("device_ctx", s.onDeviceContextTokens)
            .putBoolean("auto_accept", s.autoAccept)
            .putInt("max_accept_mb", s.maxAcceptMb)
            .putFloat("radius", s.radiusMeters.toFloat())
            .putBoolean("require_psts", s.requireProvisionedSts)
            .apply()
    }
}
