package dev.zcpmap.app.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.zcpmap.app.platform.CheckLevel
import dev.zcpmap.app.platform.SelfCheck
import dev.zcpmap.app.settings.AgentMode
import dev.zcpmap.app.settings.AgentSettings

@Composable
internal fun SetupDialog(
    current: AgentSettings,
    importState: ImportState,
    onImportModel: () -> Unit,
    onSave: (AgentSettings, String?) -> List<String>,
    onClose: () -> Unit,
) {
    var mode by remember { mutableStateOf(current.mode) }
    var serverUrl by remember { mutableStateOf(current.serverUrl) }
    var serverModel by remember { mutableStateOf(current.serverModel) }
    var serverToken by remember { mutableStateOf("") }
    var tokenEdited by remember { mutableStateOf(false) }
    var serverNative by remember { mutableStateOf(current.serverNativeTools) }
    var deviceNative by remember { mutableStateOf(current.onDeviceNativeTools) }
    var deviceGpu by remember { mutableStateOf(current.onDeviceGpu) }
    var deviceCtx by remember { mutableStateOf(current.onDeviceContextTokens.toString()) }
    var autoAccept by remember { mutableStateOf(current.autoAccept) }
    var maxAcceptMb by remember { mutableStateOf(current.maxAcceptMb.toString()) }
    var radius by remember { mutableStateOf(current.radiusMeters.toString()) }
    var requirePsts by remember { mutableStateOf(current.requireProvisionedSts) }
    var allowCode by remember { mutableStateOf(current.allowCodeCheck) }
    var errors by remember { mutableStateOf(emptyList<String>()) }
    val modelName = (importState as? ImportState.Done)?.name ?: current.modelFileName

    AlertDialog(
        onDismissRequest = onClose,
        containerColor = Tac.panel,
        title = { Mono("SETUP", Tac.green, 13, FontWeight.Bold) },
        text = {
            Column(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Mono("AGENT (none of these uses a cloud API)", Tac.dim, 10, FontWeight.Bold)
                AgentMode.entries.forEach { m ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = mode == m, onClick = { mode = m }, colors = RadioButtonDefaults.colors(selectedColor = Tac.green))
                        Mono(m.label, if (mode == m) Tac.text else Tac.dim, 11)
                    }
                }
                when (mode) {
                    AgentMode.RULES -> {
                        Mono("Typed commands drive the phone: 'share photo.jpg', 'scan', 'wipe all'. Incoming offers are decided by these rules:", Tac.dim, 10)
                        Toggle("Auto-accept incoming files", autoAccept) { autoAccept = it }
                        Field("Largest file to accept (MB)", maxAcceptMb, number = true) { maxAcceptMb = it }
                    }
                    AgentMode.ON_DEVICE -> {
                        Mono("Runs a .litertlm model on this phone, fully offline (e.g. Gemma3-1B-IT from huggingface.co/litert-community).", Tac.dim, 10)
                        Mono("Model: ${modelName ?: "none imported"}", if (modelName != null) Tac.green else Tac.amber, 10)
                        when (importState) {
                            is ImportState.Copying -> Mono("copying ${importState.name}: ${importState.bytes shr 20} MB…", Tac.amber, 10)
                            is ImportState.Failed -> Mono("import failed: ${importState.reason}", Tac.red, 10)
                            else -> Unit
                        }
                        OutlinedButton(onClick = onImportModel, enabled = importState !is ImportState.Copying) { Mono("IMPORT MODEL FILE", Tac.text, 10, FontWeight.Bold) }
                        Field("Context tokens (must match the model file)", deviceCtx, number = true) { deviceCtx = it }
                        Toggle("Try GPU first (falls back to CPU automatically)", deviceGpu) { deviceGpu = it }
                        Toggle("Model has native tool calling (FunctionGemma, Gemma 3n)", deviceNative) { deviceNative = it }
                    }
                    AgentMode.OWN_SERVER -> {
                        Mono("Your own model server on the same Wi-Fi: Ollama, LM Studio, llama.cpp or vLLM. Plain http:// works only for local addresses.", Tac.dim, 10)
                        Field("Server address, e.g. http://192.168.1.20:11434", serverUrl) { serverUrl = it }
                        Field("Model name, e.g. qwen2.5:7b-instruct", serverModel) { serverModel = it }
                        Field("Access token (optional, leave empty to keep)", serverToken, secret = true) { serverToken = it; tokenEdited = true }
                        Toggle("Server supports native tool calling", serverNative) { serverNative = it }
                    }
                }
                Spacer(Modifier.height(4.dp))
                Mono("MESH", Tac.dim, 10, FontWeight.Bold)
                Field("Distance bound radius (m)", radius, number = true) { radius = it }
                Toggle("Only allow phones with provisioned STS (relay-proof distance)", requirePsts) { requirePsts = it }
                if (!requirePsts) Mono("Phones without it can connect, but their distance could be faked by a relay, so every transfer with them waits for your APPROVE tap.", Tac.amber, 10)
                Toggle("Allow phones without UWB (both people compare a 6-digit code)", allowCode) { allowCode = it }
                if (allowCode) Mono("Used only when UWB isn't possible. Turn it on on both phones. Each transfer on such a connection waits for your APPROVE tap.", Tac.amber, 10)
                errors.forEach { Mono("• $it", Tac.red, 10) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val parsed = current.copy(
                    mode = mode,
                    serverUrl = serverUrl.trim(), serverModel = serverModel.trim(), serverNativeTools = serverNative,
                    modelFileName = modelName, onDeviceNativeTools = deviceNative, onDeviceGpu = deviceGpu,
                    onDeviceContextTokens = deviceCtx.trim().toIntOrNull() ?: -1,
                    autoAccept = autoAccept, maxAcceptMb = maxAcceptMb.trim().toIntOrNull() ?: -1,
                    radiusMeters = radius.trim().toDoubleOrNull() ?: -1.0,
                    requireProvisionedSts = requirePsts,
                    allowCodeCheck = allowCode,
                )
                errors = onSave(parsed, if (tokenEdited) serverToken else null)
                if (errors.isEmpty()) onClose()
            }) { Mono("SAVE", Tac.green, 11, FontWeight.Bold) }
        },
        dismissButton = { TextButton(onClick = onClose) { Mono("CANCEL", Tac.dim, 11) } },
    )
}

@Composable
private fun Toggle(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) { Mono(label, Tac.text, 10) }
        Switch(checked = value, onCheckedChange = onChange, colors = SwitchDefaults.colors(checkedThumbColor = Tac.bg, checkedTrackColor = Tac.green))
    }
}

@Composable
private fun Field(label: String, value: String, number: Boolean = false, secret: Boolean = false, onChange: (String) -> Unit) {
    OutlinedTextField(
        value = value, onValueChange = { if (it.length <= 300) onChange(it) },
        label = { Mono(label, Tac.dim, 9) },
        singleLine = true,
        textStyle = TextStyle(fontFamily = Tac.mono, fontSize = 11.sp, color = Tac.text),
        keyboardOptions = KeyboardOptions(keyboardType = if (number) KeyboardType.Decimal else if (secret) KeyboardType.Password else KeyboardType.Uri),
        visualTransformation = if (secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Tac.green, unfocusedBorderColor = Tac.grid, cursorColor = Tac.green),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
internal fun SelfTestDialog(checks: List<SelfCheck>, onAction: (dev.zcpmap.app.platform.SelfAction) -> Unit, onClose: () -> Unit) {
    val fails = checks.count { it.level == CheckLevel.FAIL }
    val warns = checks.count { it.level == CheckLevel.WARN }
    AlertDialog(
        onDismissRequest = onClose,
        containerColor = Tac.panel,
        title = {
            Mono(
                if (fails == 0) "SELF-TEST PASSED${if (warns > 0) " ($warns warning${if (warns > 1) "s" else ""})" else ""}" else "SELF-TEST: $fails PROBLEM${if (fails > 1) "S" else ""}",
                if (fails == 0) Tac.green else Tac.red, 13, FontWeight.Bold,
            )
        },
        text = {
            Column(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                checks.forEach { c ->
                    val color = when (c.level) { CheckLevel.PASS -> Tac.green; CheckLevel.WARN -> Tac.amber; CheckLevel.FAIL -> Tac.red }
                    Column {
                        Mono("${c.level.name.padEnd(4)}  ${c.name}", color, 11, FontWeight.Bold)
                        Mono(c.detail, Tac.text, 10)
                        c.fix?.let { Mono("fix: $it", Tac.dim, 10) }
                        c.action?.let { a ->
                            OutlinedButton(onClick = { onAction(a) }) { Mono(a.label, Tac.amber, 10, FontWeight.Bold) }
                        }
                    }
                }
                Mono("Run this on both phones. Then switch both ONLINE and hold them within the radius.", Tac.dim, 10)
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Mono("CLOSE", Tac.green, 11, FontWeight.Bold) } },
    )
}
