package dev.zcpmap.keystore

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.zcpmap.security.CryptoEngine
import dev.zcpmap.security.IdentityEndorsement
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on a real phone or emulator: `./gradlew :core:keystore:connectedDebugAndroidTest`.
 * Exercises the real Android Keystore (StrongBox / TEE / software, whatever the device has).
 */
@RunWith(AndroidJUnit4::class)
class KeystoreInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun identityIsStableAndSignaturesVerify() {
        val a = AndroidKeystoreIdentity.loadOrCreate(context)
        val b = AndroidKeystoreIdentity.loadOrCreate(context)
        assertArrayEquals("identity must survive reloads", a.publicKey, b.publicKey)
        val msg = "zcp-map instrumented".toByteArray()
        assertTrue(CryptoEngine.ed25519Verify(a.publicKey, msg, a.sign(msg)))
        assertTrue(CryptoEngine.ed25519Verify(b.publicKey, msg, b.sign(msg)))
        android.util.Log.i("ZcpKeystoreTest", "identity level: ${a.securityLevel.label} hardware=${a.securityLevel.hardwareBacked}")
    }

    @Test
    fun endorsementFromKeystoreIdentityVerifies() {
        val id = AndroidKeystoreIdentity.loadOrCreate(context)
        val st = CryptoEngine.generateX25519()
        val now = System.currentTimeMillis()
        val e = IdentityEndorsement.issue(id, st.publicKey, now - 1000, now + 600_000)
        val decoded = IdentityEndorsement.decode(e.encode())!!
        assertTrue(decoded.verify(st.publicKey, now) is dev.zcpmap.security.CryptoResult.Ok)
    }

    @Test
    fun vaultRoundTrip() {
        val v = KeystoreSecretVault(context)
        v.put("test_secret", "s3cret-value-1234567890")
        assertEquals("s3cret-value-1234567890", v.get("test_secret"))
        v.delete("test_secret")
        assertNull(v.get("test_secret"))
    }
}
