package dev.zcpmap.app

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zcpmap.agent.BackendOutcome
import dev.zcpmap.agent.ChatItem
import dev.zcpmap.agent.OnDeviceBackend
import dev.zcpmap.agent.ToolCatalog
import dev.zcpmap.app.di.NodeGraph
import dev.zcpmap.app.platform.CheckLevel
import dev.zcpmap.app.platform.DeviceSelfTest
import dev.zcpmap.app.platform.LiteRtLmEngine
import dev.zcpmap.app.settings.AgentMode
import dev.zcpmap.app.settings.AgentSettings
import dev.zcpmap.app.settings.SettingsStore
import dev.zcpmap.security.CryptoEngine
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * On a real phone (or emulator): `./gradlew :app:connectedDebugAndroidTest`.
 * Run on each of your two UWB phones; the log line "ZcpSelfTest" shows the device report.
 */
@RunWith(AndroidJUnit4::class)
class AppInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun settingsRoundTrip() {
        val store = SettingsStore(context)
        val s = AgentSettings(mode = AgentMode.OWN_SERVER, serverUrl = "http://192.168.1.20:11434", serverModel = "qwen2.5:7b-instruct", radiusMeters = 2.5)
        store.save(s)
        assertEquals(s, store.load())
        store.save(AgentSettings())
    }

    @Test
    fun nodeBootsWithRuleAgentAndIdentitySigns() = runBlocking {
        val g = NodeGraph.create(context, AgentSettings(mode = AgentMode.RULES))
        try {
            val msg = "boot".toByteArray()
            assertTrue(CryptoEngine.ed25519Verify(g.identity.publicKey, msg, g.identity.sign(msg)))
            assertTrue(g.agent.label.contains("Rule"))
            assertTrue(g.coordinator.localFingerprint.startsWith("zcp1:"))
        } finally {
            g.shutdown()
        }
    }

    @Test
    fun selfTestProducesAFullReport() = runBlocking {
        val g = NodeGraph.create(context, AgentSettings())
        try {
            val checks = DeviceSelfTest.run(context, g, AgentSettings())
            checks.forEach { android.util.Log.i("ZcpSelfTest", "${it.level} ${it.name}: ${it.detail}${it.fix?.let { f -> " (fix: $f)" } ?: ""}") }
            val names = checks.map { it.name }
            listOf("Permissions", "Bluetooth", "UWB radio", "Identity key", "Clock", "Agent").forEach { assertTrue("missing check $it", it in names) }
            assertEquals(CheckLevel.PASS, checks.first { it.name == "Agent" }.level)
        } finally {
            g.shutdown()
        }
    }

    @Test
    fun onDeviceModeWithoutModelFailsCleanly() = runBlocking {
        val engine = LiteRtLmEngine(File(context.cacheDir, "missing.litertlm"), useGpu = false, maxNumTokens = 4096, cacheDir = context.cacheDir)
        val backend = OnDeviceBackend(engine, nativeTools = false)
        val out = backend.complete("system", listOf(ChatItem.User("hello")), ToolCatalog.all)
        assertTrue("expected Fatal, got $out", out is BackendOutcome.Fatal)
        assertTrue((out as BackendOutcome.Fatal).detail.contains("import", ignoreCase = true))
        backend.close()
    }
}
