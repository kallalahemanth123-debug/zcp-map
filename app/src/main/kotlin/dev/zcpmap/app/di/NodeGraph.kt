package dev.zcpmap.app.di

import android.content.Context
import android.os.BatteryManager
import android.os.PowerManager
import android.os.StatFs
import dev.zcpmap.agent.AgentController
import dev.zcpmap.agent.AgentKernel
import dev.zcpmap.agent.CoordinatorMeshControl
import dev.zcpmap.agent.KernelConfig
import dev.zcpmap.agent.LocalServerConfig
import dev.zcpmap.agent.OnDeviceBackend
import dev.zcpmap.agent.OpenAiCompatibleBackend
import dev.zcpmap.agent.RuleBasedAgent
import dev.zcpmap.agent.RulePolicy
import dev.zcpmap.agent.SecurityAirlock
import dev.zcpmap.agent.ToolRouter
import dev.zcpmap.app.platform.DeviceSelfTest
import dev.zcpmap.app.platform.LiteRtLmEngine
import dev.zcpmap.app.settings.AgentMode
import dev.zcpmap.app.settings.AgentSettings
import dev.zcpmap.keystore.AndroidKeystoreIdentity
import dev.zcpmap.keystore.KeystoreSecretVault
import dev.zcpmap.mesh.DeviceConstraints
import dev.zcpmap.mesh.DeviceConstraintsPort
import dev.zcpmap.mesh.MeshPolicy
import dev.zcpmap.mesh.MeshSessionCoordinator
import dev.zcpmap.mesh.SandboxFileStore
import dev.zcpmap.mesh.ThermalLevel
import dev.zcpmap.security.IdentitySigner
import dev.zcpmap.security.StaticKeyRotator
import dev.zcpmap.transport.P2PTransportEngine
import dev.zcpmap.transport.UwbProximityManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.withContext
import java.io.File

/** Reads battery, charging, thermal and storage state for manifests and contract evaluation. */
class AndroidDeviceConstraints(private val context: Context, private val sandboxRoot: File) : DeviceConstraintsPort {
    private val battery = context.getSystemService(BatteryManager::class.java)
    private val power = context.getSystemService(PowerManager::class.java)

    override fun current(): DeviceConstraints {
        val pct = battery?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)?.takeIf { it in 0..100 } ?: 0
        val charging = battery?.isCharging ?: false
        val thermal = when (power?.currentThermalStatus ?: PowerManager.THERMAL_STATUS_NONE) {
            PowerManager.THERMAL_STATUS_NONE, PowerManager.THERMAL_STATUS_LIGHT -> ThermalLevel.NOMINAL
            PowerManager.THERMAL_STATUS_MODERATE -> ThermalLevel.ELEVATED
            PowerManager.THERMAL_STATUS_SEVERE -> ThermalLevel.SEVERE
            else -> ThermalLevel.CRITICAL
        }
        val free = try { StatFs(sandboxRoot.path).availableBytes } catch (_: IllegalArgumentException) { 0L }
        return DeviceConstraints(pct, charging, thermal, free)
    }
}

/**
 * Manual dependency graph for one node. Built off the main thread because Keystore key generation
 * (especially StrongBox) can take hundreds of milliseconds. Rebuilt whenever SETUP changes (offline only).
 */
class NodeGraph private constructor(
    val identity: IdentitySigner,
    val vault: KeystoreSecretVault,
    val coordinator: MeshSessionCoordinator,
    val agent: AgentController,
    val transport: P2PTransportEngine,
    val rotator: StaticKeyRotator,
    val sandbox: SandboxFileStore,
    val settings: AgentSettings,
    val scope: CoroutineScope,
    private val closeables: List<AutoCloseable>,
) {
    fun shutdown() {
        agent.stop()
        transport.shutdown()
        rotator.close()
        closeables.forEach { runCatching { it.close() } }
        scope.cancel()
    }

    companion object {
        /** Optional bearer token for the operator's own model server (kept in the Keystore vault). */
        const val SERVER_TOKEN_NAME = "server_token"

        suspend fun create(context: Context, settings: AgentSettings): NodeGraph = withContext(Dispatchers.IO) {
            val app = context.applicationContext
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val identity = AndroidKeystoreIdentity.loadOrCreate(app)
            val vault = KeystoreSecretVault(app)
            val rotator = StaticKeyRotator(identity, System::currentTimeMillis)
            val sandboxRoot = File(app.noBackupFilesDir, "sandbox").apply { mkdirs() }
            val sandbox = SandboxFileStore(sandboxRoot, inboxQuotaBytes = 2L shl 30)
            val transport = P2PTransportEngine(app, scope)
            val ranging = UwbProximityManager(app)
            val device = AndroidDeviceConstraints(app, sandboxRoot)
            val policy = MeshPolicy(
                maxDistanceMeters = settings.radiusMeters,
                requireProvisionedSts = settings.requireProvisionedSts,
                allowCodeCheckWithoutUwb = settings.allowCodeCheck,
            )
            val coordinator = MeshSessionCoordinator(
                transport = transport,
                ranging = ranging,
                identity = identity,
                rotator = rotator,
                sandbox = sandbox,
                device = device,
                policy = policy,
                agentModel = settings.mode.manifestId,
                scope = scope,
            )
            val control = CoordinatorMeshControl(coordinator)
            val serverToken = { vault.get(SERVER_TOKEN_NAME) }
            val airlock = SecurityAirlock(control, secretCanaries = { listOfNotNull(serverToken()) })
            val router = ToolRouter(control, airlock)
            val closeables = ArrayList<AutoCloseable>()
            val agent: AgentController = when (settings.mode) {
                AgentMode.RULES -> RuleBasedAgent(
                    control, router,
                    RulePolicy(autoAccept = settings.autoAccept, maxAcceptBytes = settings.maxAcceptMb.toLong() shl 20),
                    coordinator.events, scope,
                )
                AgentMode.OWN_SERVER -> {
                    val backend = OpenAiCompatibleBackend(
                        LocalServerConfig(
                            baseUrl = settings.serverUrl, model = settings.serverModel,
                            token = serverToken(), nativeTools = settings.serverNativeTools,
                        ),
                    )
                    closeables += backend
                    AgentKernel(control, router, backend, KernelConfig(), coordinator.events, scope)
                }
                AgentMode.ON_DEVICE -> {
                    val file = File(DeviceSelfTest.modelDir(app), settings.modelFileName ?: "none.litertlm")
                    val engine = LiteRtLmEngine(file, settings.onDeviceGpu, settings.onDeviceContextTokens, app.cacheDir)
                    val backend = OnDeviceBackend(
                        engine, nativeTools = settings.onDeviceNativeTools,
                        // ~3 characters per token, keeping a quarter of the window for the reply.
                        contextBudgetChars = settings.onDeviceContextTokens * 9 / 4,
                    )
                    closeables += backend
                    AgentKernel(control, router, backend, KernelConfig(maxHistoryItems = 16, maxToolRoundsPerTurn = 6), coordinator.events, scope)
                }
            }
            NodeGraph(identity, vault, coordinator, agent, transport, rotator, sandbox, settings, scope, closeables)
        }
    }
}
