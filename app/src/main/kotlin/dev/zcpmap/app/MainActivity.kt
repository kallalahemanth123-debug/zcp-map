package dev.zcpmap.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import dev.zcpmap.app.presentation.MeshAgentViewModel
import dev.zcpmap.app.presentation.MeshTerminalScreen

class MainActivity : ComponentActivity() {

    private val vm: MeshAgentViewModel by viewModels { MeshAgentViewModel.Factory(application) }
    private var permissionsGranted by mutableStateOf(false)

    private val requestPermissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
        permissionsGranted = REQUIRED.all { result[it] == true || granted(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Session transcripts, fingerprints and the API key dialog must not leak into screenshots or Recents.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        permissionsGranted = REQUIRED.all(::granted)
        setContent {
            if (permissionsGranted) {
                MeshTerminalScreen(vm)
            } else {
                PermissionGate { requestPermissions.launch(REQUIRED) }
            }
        }
        if (!permissionsGranted) requestPermissions.launch(REQUIRED)
    }

    private fun granted(p: String) = ContextCompat.checkSelfPermission(this, p) == PackageManager.PERMISSION_GRANTED

    companion object {
        val REQUIRED = arrayOf(
            Manifest.permission.UWB_RANGING,
            Manifest.permission.NEARBY_WIFI_DEVICES,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.ACCESS_FINE_LOCATION,
        )
    }
}

@androidx.compose.runtime.Composable
private fun PermissionGate(onRequest: () -> Unit) {
    Column(
        Modifier.fillMaxSize().background(Color(0xFF05080A)).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("ZCP-MAP needs radio permissions", color = Color(0xFF39FF9E), fontFamily = FontFamily.Monospace)
        Text(
            "UWB ranging proves physical proximity. Nearby (Bluetooth/Wi-Fi) and Wi-Fi Aware carry encrypted frames between devices. " +
                "Location permission is required by Nearby on some devices; this app never computes your geographic position.",
            color = Color(0xFFB9D3CF), fontFamily = FontFamily.Monospace,
        )
        Button(onClick = onRequest) { Text("GRANT", fontFamily = FontFamily.Monospace) }
    }
}
