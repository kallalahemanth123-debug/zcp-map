package dev.zcpmap.app.presentation

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import dev.zcpmap.agent.KernelStatus
import dev.zcpmap.agent.TranscriptKind
import dev.zcpmap.agent.UsageTotals
import dev.zcpmap.app.di.NodeGraph
import dev.zcpmap.app.platform.DeviceSelfTest
import dev.zcpmap.app.platform.SelfCheck
import dev.zcpmap.app.settings.AgentMode
import dev.zcpmap.app.settings.AgentSettings
import dev.zcpmap.app.settings.SettingsStore
import dev.zcpmap.mesh.LogChannel
import dev.zcpmap.mesh.MeshEvent
import dev.zcpmap.mesh.PeerSnapshot
import dev.zcpmap.mesh.PendingApproval
import dev.zcpmap.mesh.RadarFix
import dev.zcpmap.protocol.LifecyclePhase
import dev.zcpmap.protocol.LifecycleState
import dev.zcpmap.protocol.TeardownReason
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

// ------------------------------------------------------------------------------------------
// UI models
// ------------------------------------------------------------------------------------------

enum class LogTone { OBSERVATION, OPERATOR, THINKING, AGENT, TOOL, RESULT, AIRLOCK, KERNEL, CRYPTO, RANGING, TRANSPORT, PROTOCOL, PEER_UNTRUSTED, ALERT }

data class LogLine(val atMillis: Long, val tone: LogTone, val text: String, val peerId: String?)

data class PeerUi(
    val peerId: String,
    val phase: LifecyclePhase,
    val noiseVerified: Boolean,
    val distanceBound: Boolean,
    val manifestVerified: Boolean,
    val provisionedSts: Boolean?,
    val fingerprintShort: String?,
    val boundDistanceMeters: Double?,
    val fix: RadarFix?,
    val bulkLink: Boolean,
    val openContracts: Int,
    val teardownReason: TeardownReason?,
)

sealed interface BootState {
    data object Booting : BootState
    data class Ready(val fingerprint: String, val identityLevel: String, val hardwareBacked: Boolean) : BootState
    data class Failed(val reason: String) : BootState
}

sealed interface ImportState {
    data object Idle : ImportState
    data class Copying(val name: String, val bytes: Long) : ImportState
    data class Done(val name: String, val bytes: Long) : ImportState
    data class Failed(val reason: String) : ImportState
}

data class MeshUiState(
    val boot: BootState = BootState.Booting,
    val meshRunning: Boolean = false,
    val settings: AgentSettings = AgentSettings(),
    val agentLabel: String = "",
    val peers: List<PeerUi> = emptyList(),
    val approvals: List<PendingApproval> = emptyList(),
    val kernel: KernelStatus = KernelStatus.Stopped,
    val usage: UsageTotals = UsageTotals(),
    val log: List<LogLine> = emptyList(),
    val selfTest: List<SelfCheck>? = null,
    val selfTestRunning: Boolean = false,
    val importState: ImportState = ImportState.Idle,
    val outbox: List<Pair<String, Long>> = emptyList(),
)

// ------------------------------------------------------------------------------------------
// ViewModel
// ------------------------------------------------------------------------------------------

@OptIn(ExperimentalCoroutinesApi::class)
class MeshAgentViewModel(app: Application) : AndroidViewModel(app) {

    private val store = SettingsStore(app)
    private val graph = MutableStateFlow<NodeGraph?>(null)
    private val boot = MutableStateFlow<BootState>(BootState.Booting)
    private val running = MutableStateFlow(false)
    private val settings = MutableStateFlow(store.load())
    private val meshLog = MutableStateFlow<List<LogLine>>(emptyList())
    private val liveFixes = MutableStateFlow<Map<String, RadarFix>>(emptyMap())
    private val selfTest = MutableStateFlow<List<SelfCheck>?>(null)
    private val selfTestRunning = MutableStateFlow(false)
    private val importState = MutableStateFlow<ImportState>(ImportState.Idle)
    private val outbox = MutableStateFlow<List<Pair<String, Long>>>(emptyList())
    private var eventJob: Job? = null

    private fun rebuild() {
        viewModelScope.launch {
            graph.value?.shutdown()
            graph.value = null
            boot.value = BootState.Booting
            try {
                val g = NodeGraph.create(getApplication(), settings.value)
                graph.value = g
                boot.value = BootState.Ready(g.coordinator.localFingerprint, g.identity.securityLevel.label, g.identity.securityLevel.hardwareBacked)
                outbox.value = g.coordinator.outboxFiles()
                observeMesh(g)
            } catch (e: Exception) {
                boot.value = BootState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    private fun observeMesh(g: NodeGraph) {
        eventJob?.cancel()
        eventJob = viewModelScope.launch {
            g.coordinator.events.collect { e ->
                when (e) {
                    is MeshEvent.Ranging -> liveFixes.value = liveFixes.value + (e.peerId to e.fix)
                    is MeshEvent.Log -> appendMesh(
                        when (e.channel) {
                            LogChannel.CRYPTO -> LogTone.CRYPTO
                            LogChannel.RANGING -> LogTone.RANGING
                            LogChannel.TRANSPORT -> LogTone.TRANSPORT
                            LogChannel.PROTOCOL -> LogTone.PROTOCOL
                            LogChannel.PEER_UNTRUSTED -> LogTone.PEER_UNTRUSTED
                        },
                        e.text, e.peerId,
                    )
                    is MeshEvent.SecurityAlert -> appendMesh(LogTone.ALERT, "${e.reason}: ${e.detail}", e.peerId)
                    is MeshEvent.StateChanged -> appendMesh(LogTone.PROTOCOL, "→ ${e.state.phase}", e.peerId)
                    is MeshEvent.TransferProgress -> if (e.bytesDone == e.totalBytes) {
                        appendMesh(LogTone.TRANSPORT, "${if (e.inbound) "received" else "sent"} ${e.totalBytes} bytes (${e.contractId})", e.peerId)
                    }
                    is MeshEvent.SettlementCompleted -> {
                        appendMesh(LogTone.CRYPTO, "settlement signed ${e.receiptHashHex.take(16)}… (${e.contractId})", e.peerId)
                        refreshOutbox()
                    }
                    else -> Unit
                }
            }
        }
    }

    private fun appendMesh(tone: LogTone, text: String, peerId: String?) {
        val l = meshLog.value
        meshLog.value = (if (l.size >= 400) l.drop(l.size - 399) else l) + LogLine(System.currentTimeMillis(), tone, text, peerId)
    }

    private val peersFlow = graph.flatMapLatest { g -> g?.coordinator?.peers ?: flowOf(emptyMap()) }
    private val approvalsFlow = graph.flatMapLatest { g -> g?.coordinator?.approvals ?: flowOf(emptyList()) }
    private val kernelFlow = graph.flatMapLatest { g -> g?.agent?.status ?: flowOf(KernelStatus.Stopped) }
    private val usageFlow = graph.flatMapLatest { g -> g?.agent?.usage ?: flowOf(UsageTotals()) }
    private val transcriptFlow = graph.flatMapLatest { g -> g?.agent?.transcript ?: flowOf(emptyList()) }

    private val mergedLog = combine(transcriptFlow, meshLog) { transcript, mesh ->
        val agentLines = transcript.map { t ->
            LogLine(
                t.atMillis,
                when (t.kind) {
                    TranscriptKind.OBSERVATION -> LogTone.OBSERVATION
                    TranscriptKind.OPERATOR -> LogTone.OPERATOR
                    TranscriptKind.THINKING -> LogTone.THINKING
                    TranscriptKind.AGENT_TEXT -> LogTone.AGENT
                    TranscriptKind.TOOL_CALL -> LogTone.TOOL
                    TranscriptKind.TOOL_RESULT -> LogTone.RESULT
                    TranscriptKind.AIRLOCK_DENIED -> LogTone.AIRLOCK
                    TranscriptKind.KERNEL -> LogTone.KERNEL
                },
                t.text, t.peerId,
            )
        }
        (agentLines + mesh).sortedBy { it.atMillis }.takeLast(400)
    }

    private val peerUi = combine(peersFlow, liveFixes) { peers, fixes -> peers.values.map { toUi(it, fixes[it.peerId]) }.sortedBy { it.peerId } }

    private data class Head(val boot: BootState, val running: Boolean, val settings: AgentSettings, val label: String)
    private data class Tools(val selfTest: List<SelfCheck>?, val running: Boolean, val import: ImportState, val outbox: List<Pair<String, Long>>)

    private val head = combine(boot, running, settings, graph) { b, r, s, g -> Head(b, r, s, g?.agent?.label ?: s.mode.label) }
    private val tools = combine(selfTest, selfTestRunning, importState, outbox) { t, r, i, o -> Tools(t, r, i, o) }
    private val agentState = combine(kernelFlow, usageFlow, approvalsFlow) { k, u, a -> Triple(k, u, a) }

    val ui: StateFlow<MeshUiState> = combine(head, peerUi, agentState, mergedLog, tools) { h, peers, ag, log, t ->
        MeshUiState(
            boot = h.boot, meshRunning = h.running, settings = h.settings, agentLabel = h.label,
            peers = peers, approvals = ag.third, kernel = ag.first, usage = ag.second, log = log,
            selfTest = t.selfTest, selfTestRunning = t.running, importState = t.import, outbox = t.outbox,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), MeshUiState(settings = settings.value))

    private fun toUi(s: PeerSnapshot, liveFix: RadarFix?): PeerUi {
        val phase = s.state.phase
        val past = { p: LifecyclePhase -> phase.ordinal >= p.ordinal && phase != LifecyclePhase.TEARDOWN }
        return PeerUi(
            peerId = s.peerId,
            phase = phase,
            noiseVerified = s.peerFingerprint != null && phase != LifecyclePhase.TEARDOWN,
            distanceBound = (s.boundDistanceMeters ?: -1.0) >= 0 && phase != LifecyclePhase.TEARDOWN,
            manifestVerified = past(LifecyclePhase.ATTESTATION_VERIFIED),
            provisionedSts = s.provisionedSts,
            fingerprintShort = s.peerFingerprint?.removePrefix("zcp1:")?.take(17),
            boundDistanceMeters = s.boundDistanceMeters,
            fix = liveFix ?: s.lastFix,
            bulkLink = s.bulkLinkActive,
            openContracts = s.openContracts.size,
            teardownReason = (s.state as? LifecycleState.Teardown)?.reason,
        )
    }

    // ------------------------------------------------------------------ actions

    fun setMeshRunning(on: Boolean) {
        val g = graph.value ?: return
        if (on == running.value) return
        viewModelScope.launch {
            if (on) {
                try {
                    g.coordinator.start()
                    g.agent.start()
                    running.value = true
                    appendMesh(LogTone.TRANSPORT, "mesh online — advertising rotating beacon; agent: ${g.agent.label}", null)
                } catch (e: Exception) {
                    appendMesh(LogTone.ALERT, "mesh start failed: ${e.message}", null)
                }
            } else {
                g.agent.stop()
                g.coordinator.stop()
                running.value = false
                liveFixes.value = emptyMap()
                appendMesh(LogTone.TRANSPORT, "mesh offline — all sessions torn down, keys zeroized", null)
            }
        }
    }

    /** Applies new settings. Only while offline: the whole node is rebuilt with the new agent. */
    fun saveSettings(new: AgentSettings, serverToken: String?): List<String> {
        if (running.value) return listOf("Switch the mesh OFFLINE before changing setup")
        val errors = new.validate()
        if (errors.isNotEmpty()) return errors
        viewModelScope.launch {
            val g = graph.value
            if (g != null && serverToken != null) {
                withContext(Dispatchers.IO) {
                    if (serverToken.isBlank()) g.vault.delete(NodeGraph.SERVER_TOKEN_NAME) else g.vault.put(NodeGraph.SERVER_TOKEN_NAME, serverToken.trim())
                }
            }
            store.save(new)
            settings.value = new
            selfTest.value = null
            rebuild()
        }
        return emptyList()
    }

    /** Copies a .litertlm file chosen in the system file picker into private storage. */
    fun importModel(uri: Uri) {
        val ctx = getApplication<Application>()
        viewModelScope.launch {
            try {
                val name = withContext(Dispatchers.IO) {
                    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                        if (c.moveToFirst()) c.getString(0) else null
                    }
                }?.let { sanitizeFileName(it) } ?: "model.litertlm"
                if (!name.endsWith(".litertlm") && !name.endsWith(".task")) {
                    importState.value = ImportState.Failed("Pick a .litertlm model file (got $name)")
                    return@launch
                }
                val dir = DeviceSelfTest.modelDir(ctx)
                val tmp = File(dir, "$name.part")
                var copied = 0L
                importState.value = ImportState.Copying(name, 0)
                withContext(Dispatchers.IO) {
                    ctx.contentResolver.openInputStream(uri)?.use { inp ->
                        tmp.outputStream().use { out ->
                            val buf = ByteArray(1 shl 20)
                            while (true) {
                                val n = inp.read(buf)
                                if (n < 0) break
                                out.write(buf, 0, n)
                                copied += n
                                if (copied % (64L shl 20) < n) importState.value = ImportState.Copying(name, copied)
                            }
                        }
                    } ?: throw IOException("cannot open the selected file")
                    // Keep exactly one model on disk.
                    dir.listFiles()?.filter { it.name != tmp.name }?.forEach { it.delete() }
                    if (!tmp.renameTo(File(dir, name))) throw IOException("could not store the model")
                }
                importState.value = ImportState.Done(name, copied)
                val s = settings.value.copy(modelFileName = name)
                store.save(s)
                settings.value = s
                if (!running.value) rebuild()
            } catch (e: Exception) {
                importState.value = ImportState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun runSelfTest() {
        if (selfTestRunning.value) return
        viewModelScope.launch {
            selfTestRunning.value = true
            try {
                selfTest.value = DeviceSelfTest.run(getApplication(), graph.value, settings.value)
            } finally {
                selfTestRunning.value = false
            }
        }
    }

    /** Applies the fix offered by a failed self-test check, then re-runs the test. */
    fun applySelfTestAction(action: dev.zcpmap.app.platform.SelfAction) {
        if (running.value) {
            appendMesh(LogTone.ALERT, "switch the mesh OFFLINE first, then tap the fix again", null)
            return
        }
        val updated = when (action) {
            dev.zcpmap.app.platform.SelfAction.ALLOW_STATIC_STS_WITH_APPROVAL -> settings.value.copy(requireProvisionedSts = false)
        }
        store.save(updated)
        settings.value = updated
        viewModelScope.launch {
            graph.value?.shutdown()
            graph.value = null
            try {
                val g = NodeGraph.create(getApplication(), updated)
                graph.value = g
                boot.value = BootState.Ready(g.coordinator.localFingerprint, g.identity.securityLevel.label, g.identity.securityLevel.hardwareBacked)
                outbox.value = g.coordinator.outboxFiles()
                observeMesh(g)
                selfTest.value = DeviceSelfTest.run(getApplication(), g, updated)
            } catch (e: Exception) {
                boot.value = BootState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun dismissSelfTest() {
        selfTest.value = null
    }

    fun refreshOutbox() {
        outbox.value = graph.value?.coordinator?.outboxFiles() ?: emptyList()
    }

    /** Copies a user-picked file into the sandbox outbox so agents can share it. */
    fun addToOutbox(uri: Uri) {
        val ctx = getApplication<Application>()
        val g = graph.value ?: return
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val name = ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                        if (c.moveToFirst()) c.getString(0) else null
                    }?.let { sanitizeFileName(it) } ?: "file.bin"
                    val dest = File(g.sandbox.root, "outbox/$name")
                    dest.parentFile?.mkdirs()
                    ctx.contentResolver.openInputStream(uri)?.use { inp -> dest.outputStream().use { inp.copyTo(it) } }
                        ?: throw IOException("cannot open the selected file")
                }
                refreshOutbox()
                appendMesh(LogTone.TRANSPORT, "added to outbox: ${outbox.value.lastOrNull()?.first ?: ""}", null)
            } catch (e: Exception) {
                appendMesh(LogTone.ALERT, "could not add file: ${e.message}", null)
            }
        }
    }

    fun submitDirective(text: String) {
        graph.value?.agent?.submitOperatorDirective(text)
    }

    fun resolveApproval(approvalId: String, approve: Boolean) {
        val g = graph.value ?: return
        viewModelScope.launch { g.coordinator.resolveApproval(approvalId, approve) }
    }

    fun terminate(peerId: String) {
        val g = graph.value ?: return
        viewModelScope.launch { g.coordinator.terminate(peerId, TeardownReason.LOCAL_REQUEST, "operator override") }
    }

    val isRuleMode: Boolean get() = settings.value.mode == AgentMode.RULES

    init {
        // Declared last so every flow above is initialized before the first rebuild runs.
        rebuild()
    }

    override fun onCleared() {
        graph.value?.shutdown()
        super.onCleared()
    }

    private fun sanitizeFileName(n: String): String =
        n.replace(Regex("[^A-Za-z0-9._-]"), "_").trim('.', '_').take(80).ifEmpty { "file.bin" }

    class Factory(private val app: Application) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(MeshAgentViewModel::class.java))
            return MeshAgentViewModel(app) as T
        }
    }
}
