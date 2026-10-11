package dev.zcpmap.app.presentation

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import dev.zcpmap.app.settings.AgentMode
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.zcpmap.agent.KernelStatus
import dev.zcpmap.mesh.PendingApproval
import dev.zcpmap.protocol.LifecyclePhase
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.cos
import kotlin.math.sin

// ------------------------------------------------------------------------------------------
// Tactical palette
// ------------------------------------------------------------------------------------------

internal object Tac {
    val bg = Color(0xFF05080A)
    val panel = Color(0xFF0B1115)
    val grid = Color(0xFF16323A)
    val gridBright = Color(0xFF1F5560)
    val text = Color(0xFFB9D3CF)
    val dim = Color(0xFF5E7A78)
    val green = Color(0xFF39FF9E)
    val cyan = Color(0xFF3AD7FF)
    val amber = Color(0xFFFFC23A)
    val red = Color(0xFFFF4D5E)
    val violet = Color(0xFFB48CFF)
    val mono = FontFamily.Monospace
}

private val TacColors = darkColorScheme(
    primary = Tac.green, onPrimary = Tac.bg, secondary = Tac.cyan, background = Tac.bg, surface = Tac.panel,
    onSurface = Tac.text, onBackground = Tac.text, error = Tac.red, outline = Tac.gridBright,
)

private fun toneColor(t: LogTone): Color = when (t) {
    LogTone.OBSERVATION -> Tac.cyan
    LogTone.OPERATOR -> Color.White
    LogTone.THINKING -> Tac.violet
    LogTone.AGENT -> Tac.green
    LogTone.TOOL -> Tac.amber
    LogTone.RESULT -> Tac.text
    LogTone.AIRLOCK -> Tac.red
    LogTone.KERNEL -> Tac.dim
    LogTone.CRYPTO -> Tac.green
    LogTone.RANGING -> Tac.cyan
    LogTone.TRANSPORT -> Tac.dim
    LogTone.PROTOCOL -> Tac.text
    LogTone.PEER_UNTRUSTED -> Tac.amber
    LogTone.ALERT -> Tac.red
}

private fun toneTag(t: LogTone): String = when (t) {
    LogTone.OBSERVATION -> "OBS"; LogTone.OPERATOR -> "OP "; LogTone.THINKING -> "THK"; LogTone.AGENT -> "AGT"
    LogTone.TOOL -> "TOOL"; LogTone.RESULT -> "RES"; LogTone.AIRLOCK -> "AIRLOCK"; LogTone.KERNEL -> "KRN"
    LogTone.CRYPTO -> "SEC"; LogTone.RANGING -> "UWB"; LogTone.TRANSPORT -> "NET"; LogTone.PROTOCOL -> "FSM"
    LogTone.PEER_UNTRUSTED -> "PEER?"; LogTone.ALERT -> "ALERT"
}

private fun phaseColor(p: LifecyclePhase): Color = when (p) {
    LifecyclePhase.IDLE, LifecyclePhase.UWB_RANGING -> Tac.dim
    LifecyclePhase.NOISE_HANDSHAKE -> Tac.amber
    LifecyclePhase.ATTESTATION_VERIFIED, LifecyclePhase.AGENT_NEGOTIATING -> Tac.green
    LifecyclePhase.TASK_EXECUTING -> Tac.cyan
    LifecyclePhase.SETTLEMENT_COMPLETE -> Tac.violet
    LifecyclePhase.TEARDOWN -> Tac.red
}

// ------------------------------------------------------------------------------------------
// Screen
// ------------------------------------------------------------------------------------------

@Composable
fun MeshTerminalScreen(vm: MeshAgentViewModel) {
    val state by vm.ui.collectAsStateWithLifecycle()
    var showSetup by rememberSaveable { mutableStateOf(false) }
    val pickModel = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(vm::importModel) }
    val pickOutbox = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(vm::addToOutbox) }
    var sendTarget by rememberSaveable { mutableStateOf<String?>(null) }
    val pickToSend = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val target = sendTarget
        sendTarget = null
        if (uri != null && target != null) vm.sendFile(target, uri)
    }
    MaterialTheme(colorScheme = TacColors) {
        Box(Modifier.fillMaxSize().background(Tac.bg)) {
            Column(
                Modifier.fillMaxSize().statusBarsPadding().imePadding().padding(horizontal = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Header(state, onToggle = vm::setMeshRunning)
                when (val b = state.boot) {
                    BootState.Booting -> Mono("Provisioning hardware identity…", Tac.amber)
                    is BootState.Failed -> Mono("BOOT FAILURE: ${b.reason}", Tac.red)
                    is BootState.Ready -> Unit
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    OutlinedButton(onClick = { showSetup = true }, enabled = !state.meshRunning) { Mono("SETUP", Tac.text, 10, FontWeight.Bold) }
                    OutlinedButton(onClick = vm::runSelfTest, enabled = !state.selfTestRunning) {
                        Mono(if (state.selfTestRunning) "TESTING…" else "SELF-TEST", Tac.text, 10, FontWeight.Bold)
                    }
                    OutlinedButton(onClick = { pickOutbox.launch(arrayOf("*/*")) }, enabled = state.boot is BootState.Ready) {
                        Mono("+ FILE", Tac.text, 10, FontWeight.Bold)
                    }
                }
                if (state.outbox.isNotEmpty()) {
                    Mono("outbox: " + state.outbox.joinToString(" · ") { "${it.first.removePrefix("outbox/")} (${humanBytes(it.second)})" }, Tac.dim, 9, maxLines = 2)
                }
                Radar(state.peers, state.settings.radiusMeters, state.meshRunning, Modifier.fillMaxWidth().aspectRatio(1.6f))
                state.peers.filter { it.codeCheck != null }.forEach { p -> CodeCheckCard(p, vm::confirmCode) }
                state.approvals.forEach { ApprovalCard(it, vm::resolveApproval) }
                PeerStrip(
                    state.peers, state.meshRunning,
                    onConnect = vm::connect,
                    onSendFile = { pid -> sendTarget = pid; pickToSend.launch(arrayOf("*/*")) },
                    onTerminate = vm::terminate,
                )
                Terminal(state.log, Modifier.weight(1f).fillMaxWidth())
                DirectiveBar(
                    enabled = state.meshRunning,
                    hint = if (state.settings.mode == AgentMode.RULES) "command: share <file> · scan · wipe all · help" else "directive to the node agent…",
                    onSend = vm::submitDirective,
                )
                Spacer(Modifier.height(4.dp))
            }
            if (showSetup) {
                SetupDialog(
                    current = state.settings,
                    importState = state.importState,
                    onImportModel = { pickModel.launch(arrayOf("*/*")) },
                    onSave = { s, token -> vm.saveSettings(s, token) },
                    onClose = { showSetup = false },
                )
            }
            state.selfTest?.let { SelfTestDialog(it, onAction = vm::applySelfTestAction, onClose = vm::dismissSelfTest) }
        }
    }
}

private fun humanBytes(n: Long): String = when {
    n >= 1L shl 30 -> "%.1f GB".format(n / (1L shl 30).toDouble())
    n >= 1L shl 20 -> "%.1f MB".format(n / (1L shl 20).toDouble())
    n >= 1L shl 10 -> "%.1f KB".format(n / (1L shl 10).toDouble())
    else -> "$n B"
}

@Composable
internal fun Mono(text: String, color: Color = Tac.text, size: Int = 11, weight: FontWeight = FontWeight.Normal, maxLines: Int = Int.MAX_VALUE) {
    Text(text, color = color, fontFamily = Tac.mono, fontSize = size.sp, fontWeight = weight, maxLines = maxLines, overflow = TextOverflow.Ellipsis)
}

@Composable
private fun Header(state: MeshUiState, onToggle: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Mono("ZCP-MAP // NODE", Tac.green, 15, FontWeight.Bold)
            val ready = state.boot as? BootState.Ready
            Mono(ready?.fingerprint?.removePrefix("zcp1:") ?: "—", Tac.dim, 10, maxLines = 1)
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Badge(ready?.identityLevel ?: "identity…", if (ready?.hardwareBacked == true) Tac.green else Tac.amber)
                Badge(kernelLabel(state.kernel), kernelColor(state.kernel))
            }
            Mono("agent: ${state.agentLabel}" + if (state.usage.requests > 0) " · tokens in ${state.usage.inputTokens} out ${state.usage.outputTokens}" else "", Tac.dim, 9, maxLines = 1)
        }
        Column(horizontalAlignment = Alignment.End) {
            Switch(
                checked = state.meshRunning,
                onCheckedChange = onToggle,
                enabled = state.boot is BootState.Ready,
                colors = SwitchDefaults.colors(checkedThumbColor = Tac.bg, checkedTrackColor = Tac.green, uncheckedTrackColor = Tac.panel),
            )
            Mono(if (state.meshRunning) "ONLINE" else "OFFLINE", if (state.meshRunning) Tac.green else Tac.dim, 10)
        }
    }
}

private fun kernelLabel(k: KernelStatus): String = when (k) {
    KernelStatus.Stopped -> "AGENT OFF"
    KernelStatus.Idle -> "AGENT IDLE"
    is KernelStatus.Thinking -> "THINKING r${k.round}"
    is KernelStatus.ExecutingTool -> "TOOL ${k.tool.take(18)}"
    is KernelStatus.Backoff -> "BACKOFF #${k.attempt}"
    is KernelStatus.Faulted -> "FAULT"
}

private fun kernelColor(k: KernelStatus): Color = when (k) {
    KernelStatus.Stopped -> Tac.dim
    KernelStatus.Idle -> Tac.green
    is KernelStatus.Thinking -> Tac.violet
    is KernelStatus.ExecutingTool -> Tac.amber
    is KernelStatus.Backoff -> Tac.amber
    is KernelStatus.Faulted -> Tac.red
}

@Composable
internal fun Badge(text: String, color: Color) {
    Box(
        Modifier.border(1.dp, color.copy(alpha = 0.7f), RoundedCornerShape(3.dp))
            .background(color.copy(alpha = 0.08f), RoundedCornerShape(3.dp))
            .padding(horizontal = 5.dp, vertical = 1.dp),
    ) { Mono(text, color, 9, FontWeight.Bold, maxLines = 1) }
}

// ------------------------------------------------------------------------------------------
// Radar
// ------------------------------------------------------------------------------------------

@Composable
private fun Radar(peers: List<PeerUi>, radius: Double, active: Boolean, modifier: Modifier) {
    val sweep by rememberInfiniteTransition(label = "sweep").animateFloat(
        initialValue = 0f, targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(3_000, easing = LinearEasing), RepeatMode.Restart), label = "angle",
    )
    val measurer = rememberTextMeasurer()
    val labelStyle = TextStyle(fontFamily = Tac.mono, fontSize = 9.sp, color = Tac.text)
    val dimStyle = TextStyle(fontFamily = Tac.mono, fontSize = 8.sp, color = Tac.dim)
    Box(modifier.border(1.dp, Tac.grid, RoundedCornerShape(6.dp)).background(Tac.panel, RoundedCornerShape(6.dp))) {
        Canvas(Modifier.fillMaxSize().padding(8.dp)) {
            // Forward-facing semicircle plus rear arc: the phone's UWB antenna array resolves azimuth in front.
            val center = Offset(size.width / 2f, size.height * 0.92f)
            val maxR = minOf(size.width / 2f, size.height * 0.88f)
            val outerMeters = (radius * 1.5).coerceAtLeast(1.0)
            fun metersToPx(m: Double) = (m / outerMeters * maxR).toFloat()

            // Range rings at whole meters + the policy radius ring.
            var m = 1.0
            while (m <= outerMeters + 1e-6) {
                val r = metersToPx(m)
                drawArc(Tac.grid, 180f, 180f, false, Offset(center.x - r, center.y - r), Size(2 * r, 2 * r), style = Stroke(1f))
                drawText(measurer, "${m.toInt()}m", Offset(center.x + r - 14f, center.y - 12f), dimStyle)
                m += 1.0
            }
            val rr = metersToPx(radius)
            drawArc(
                Tac.green.copy(alpha = 0.6f), 180f, 180f, false, Offset(center.x - rr, center.y - rr), Size(2 * rr, 2 * rr),
                style = Stroke(1.5f, pathEffect = PathEffect.dashPathEffect(floatArrayOf(8f, 6f))),
            )
            // Bearing spokes every 30°.
            for (deg in -90..90 step 30) {
                val a = Math.toRadians(deg.toDouble() - 90.0)
                drawLine(Tac.grid, center, Offset(center.x + (maxR * cos(a)).toFloat(), center.y + (maxR * sin(a)).toFloat()), 1f)
            }
            if (active) drawSweep(center, maxR, sweep)

            peers.forEachIndexed { i, p ->
                val fix = p.fix
                val color = when {
                    p.teardownReason != null -> Tac.red
                    p.manifestVerified -> Tac.green
                    p.phase == LifecyclePhase.NOISE_HANDSHAKE -> Tac.amber
                    else -> Tac.dim
                }
                if (fix == null) {
                    // Unranged beacon: park it on the outer rim, spread by index; position carries no meaning.
                    val a = Math.toRadians(-80.0 + (i * 23) % 160 - 90.0)
                    val pos = Offset(center.x + (maxR * cos(a)).toFloat(), center.y + (maxR * sin(a)).toFloat())
                    drawCircle(color, 4f, pos, style = Stroke(1.5f))
                    drawText(measurer, p.peerId.takeLast(4), pos + Offset(6f, -6f), dimStyle)
                } else {
                    val r = metersToPx(fix.distanceMeters.coerceAtMost(outerMeters))
                    val az = fix.azimuthDegrees
                    if (az == null) {
                        // No angle-of-arrival: draw the distance as an arc.
                        drawArc(color.copy(alpha = 0.8f), 200f, 140f, false, Offset(center.x - r, center.y - r), Size(2 * r, 2 * r), style = Stroke(3f))
                        drawText(measurer, "${p.peerId.takeLast(4)} %.2fm".format(fix.distanceMeters), Offset(center.x + 4f, center.y - r - 14f), labelStyle)
                    } else {
                        val a = Math.toRadians(az.coerceIn(-90.0, 90.0) - 90.0)
                        val pos = Offset(center.x + (r * cos(a)).toFloat(), center.y + (r * sin(a)).toFloat())
                        drawCircle(color.copy(alpha = 0.25f), 14f, pos)
                        drawCircle(color, 5f, pos)
                        drawText(measurer, "${p.peerId.takeLast(4)} %.2fm %+.0f°".format(fix.distanceMeters, az), pos + Offset(8f, -16f), labelStyle)
                    }
                }
            }
            drawCircle(Tac.cyan, 4f, center)
        }
        Column(Modifier.align(Alignment.TopStart).padding(8.dp)) {
            Mono("UWB STS RADAR", Tac.dim, 9, FontWeight.Bold)
            Mono("bound ≤ %.1fm".format(radius), Tac.green, 9)
        }
    }
}

private fun DrawScope.drawSweep(center: Offset, radius: Float, angle: Float) {
    val a = (angle % 180f) + 180f
    drawArc(
        brush = Brush.sweepGradient(listOf(Color.Transparent, Tac.green.copy(alpha = 0.18f), Color.Transparent), center),
        startAngle = a - 25f, sweepAngle = 25f, useCenter = true,
        topLeft = Offset(center.x - radius, center.y - radius), size = Size(2 * radius, 2 * radius),
    )
}

// ------------------------------------------------------------------------------------------
// Peers, approvals
// ------------------------------------------------------------------------------------------

@Composable
private fun PeerStrip(
    peers: List<PeerUi>,
    running: Boolean,
    onConnect: (String) -> Unit,
    onSendFile: (String) -> Unit,
    onTerminate: (String) -> Unit,
) {
    if (peers.isEmpty()) {
        Mono(if (running) "no phones found yet · the other phone must be ONLINE with the app open" else "switch ONLINE to find nearby phones", Tac.dim, 10)
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        peers.take(4).forEach { p ->
            Row(
                Modifier.fillMaxWidth().border(1.dp, Tac.grid, RoundedCornerShape(4.dp)).padding(6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(Modifier.size(8.dp).background(phaseColor(p.phase), RoundedCornerShape(4.dp)))
                Spacer(Modifier.width(6.dp))
                Column(Modifier.weight(1f)) {
                    Mono("phone ${p.peerId.takeLast(4)} · ${PlainLanguage.status(p)}", phaseColor(p.phase), 10, FontWeight.Bold, maxLines = 2)
                    if (p.phase != LifecyclePhase.IDLE) {
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            Badge("NOISE", if (p.noiseVerified) Tac.green else Tac.dim)
                            if (p.codeVerified || p.codeCheck != null) {
                                Badge("CODE", if (p.codeVerified) Tac.green else Tac.amber)
                            } else {
                                Badge(
                                    if (p.distanceBound) "UWB %.2fm".format(p.boundDistanceMeters ?: 0.0) else "UWB",
                                    if (p.distanceBound) Tac.green else Tac.dim,
                                )
                                Badge(if (p.provisionedSts == false) "STS-S" else "STS-P", if (p.provisionedSts == true) Tac.green else Tac.dim)
                            }
                            Badge("MANIFEST", if (p.manifestVerified) Tac.green else Tac.dim)
                            if (p.bulkLink) Badge("NAN", Tac.cyan)
                        }
                    }
                    p.fingerprintShort?.let { Mono(it, Tac.dim, 9, maxLines = 1) }
                    p.failure?.let { Mono(it, Tac.red, 9) }
                }
                Column(horizontalAlignment = Alignment.End) {
                    when (p.phase) {
                        LifecyclePhase.IDLE -> Button(
                            onClick = { onConnect(p.peerId) }, enabled = running,
                            colors = ButtonDefaults.buttonColors(containerColor = Tac.green, contentColor = Tac.bg),
                        ) { Mono(if (p.failure != null) "RETRY" else "CONNECT", Tac.bg, 10, FontWeight.Bold) }
                        LifecyclePhase.ATTESTATION_VERIFIED, LifecyclePhase.AGENT_NEGOTIATING, LifecyclePhase.SETTLEMENT_COMPLETE -> {
                            Button(
                                onClick = { onSendFile(p.peerId) },
                                colors = ButtonDefaults.buttonColors(containerColor = Tac.green, contentColor = Tac.bg),
                            ) { Mono("SEND FILE", Tac.bg, 10, FontWeight.Bold) }
                            TextButton(onClick = { onTerminate(p.peerId) }) { Mono("DISCONNECT", Tac.red, 9, FontWeight.Bold) }
                        }
                        LifecyclePhase.TEARDOWN -> Mono("retry in a few s", Tac.dim, 9)
                        else -> TextButton(onClick = { onTerminate(p.peerId) }) { Mono("CANCEL", Tac.red, 10, FontWeight.Bold) }
                    }
                }
            }
        }
    }
}

@Composable
private fun CodeCheckCard(p: PeerUi, onConfirm: (String, Boolean) -> Unit) {
    val c = p.codeCheck ?: return
    Column(
        Modifier.fillMaxWidth().border(1.dp, Tac.amber, RoundedCornerShape(4.dp)).background(Tac.amber.copy(alpha = 0.06f)).padding(10.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Mono("COMPARE CODES · phone ${p.peerId.takeLast(4)}", Tac.amber, 10, FontWeight.Bold)
        Text(c.code, color = Tac.green, fontFamily = Tac.mono, fontSize = 34.sp, fontWeight = FontWeight.Bold)
        Mono("The other phone must show exactly this code. If it does, tap CODES MATCH on both phones. If it doesn't, tap DIFFERENT.", Tac.text, 10)
        if (!c.confirmedHere) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { onConfirm(p.peerId, true) }, colors = ButtonDefaults.buttonColors(containerColor = Tac.green, contentColor = Tac.bg)) {
                    Mono("CODES MATCH", Tac.bg, 10, FontWeight.Bold)
                }
                OutlinedButton(onClick = { onConfirm(p.peerId, false) }) { Mono("DIFFERENT", Tac.red, 10, FontWeight.Bold) }
            }
        } else {
            Mono(if (c.confirmedByPeer) "Both confirmed — finishing…" else "Confirmed here · now tap CODES MATCH on the other phone", Tac.dim, 10)
        }
    }
}

@Composable
private fun ApprovalCard(a: PendingApproval, onResolve: (String, Boolean) -> Unit) {
    Column(
        Modifier.fillMaxWidth().border(1.dp, Tac.amber, RoundedCornerShape(4.dp)).background(Tac.amber.copy(alpha = 0.06f)).padding(8.dp),
    ) {
        Mono("POLICY OVERRIDE REQUIRED · ${a.peerId}", Tac.amber, 10, FontWeight.Bold)
        Mono(a.summary, Tac.text, 10)
        Mono("contract ${a.contractId}", Tac.dim, 9)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 4.dp)) {
            Button(onClick = { onResolve(a.approvalId, true) }, colors = ButtonDefaults.buttonColors(containerColor = Tac.green, contentColor = Tac.bg)) {
                Mono("APPROVE", Tac.bg, 10, FontWeight.Bold)
            }
            OutlinedButton(onClick = { onResolve(a.approvalId, false) }) { Mono("DENY", Tac.red, 10, FontWeight.Bold) }
        }
    }
}

// ------------------------------------------------------------------------------------------
// Terminal log + operator directive
// ------------------------------------------------------------------------------------------

@Composable
private fun Terminal(lines: List<LogLine>, modifier: Modifier) {
    val listState = rememberLazyListState()
    LaunchedEffect(lines.size) { if (lines.isNotEmpty()) listState.animateScrollToItem(lines.size - 1) }
    val fmt = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }
    LazyColumn(
        state = listState,
        modifier = modifier.border(1.dp, Tac.grid, RoundedCornerShape(6.dp)).background(Color.Black, RoundedCornerShape(6.dp)).padding(6.dp),
    ) {
        items(lines) { l ->
            Row {
                Mono(fmt.format(Date(l.atMillis)), Tac.dim, 9)
                Spacer(Modifier.width(4.dp))
                Mono(toneTag(l.tone).padEnd(5), toneColor(l.tone), 9, FontWeight.Bold)
                Spacer(Modifier.width(4.dp))
                Mono(
                    (l.peerId?.let { "[${it.takeLast(4)}] " } ?: "") + l.text,
                    if (l.tone == LogTone.PEER_UNTRUSTED) Tac.amber else Tac.text, 9,
                )
            }
        }
    }
}

@Composable
private fun DirectiveBar(enabled: Boolean, hint: String, onSend: (String) -> Unit) {
    var text by rememberSaveable { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
            value = text, onValueChange = { if (it.length <= 1000) text = it }, enabled = enabled,
            placeholder = { Mono(hint, Tac.dim, 10) },
            textStyle = TextStyle(fontFamily = Tac.mono, fontSize = 11.sp, color = Tac.text),
            singleLine = true, modifier = Modifier.weight(1f),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { if (text.isNotBlank()) { onSend(text); text = "" } }),
            colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Tac.green, unfocusedBorderColor = Tac.grid, cursorColor = Tac.green),
        )
        Spacer(Modifier.width(6.dp))
        Button(
            onClick = { if (text.isNotBlank()) { onSend(text); text = "" } }, enabled = enabled && text.isNotBlank(),
            colors = ButtonDefaults.buttonColors(containerColor = Tac.green, contentColor = Tac.bg),
        ) { Mono("SEND", Tac.bg, 10, FontWeight.Bold) }
    }
}
