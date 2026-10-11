package dev.zcpmap.keystore

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import dev.zcpmap.security.CryptoEngine
import dev.zcpmap.security.CryptoError
import dev.zcpmap.security.IdentitySecurityLevel
import dev.zcpmap.security.IdentitySigner
import dev.zcpmap.security.SecretBytes
import dev.zcpmap.security.SoftwareEd25519Signer
import dev.zcpmap.security.zeroize
import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/*
 * Long-term Ed25519 identity backed by Android Keystore.
 *
 * Preference order (first that works AND passes a sign/verify self-test wins):
 *   1. Native Ed25519 in StrongBox                  (not offered by current StrongBox chips; tried for future devices)
 *   2. Native Ed25519 in the TEE (KeyMint 2+, API 33+)
 *   3. Ed25519 seed sealed with an AES-256-GCM key in StrongBox
 *   4. Ed25519 seed sealed with an AES-256-GCM key in the TEE
 *
 * In (1)/(2) the private key never enters app memory. In (3)/(4) the 32-byte seed is decrypted into
 * a SecretBytes only for the duration of one signature and zeroized immediately afterwards; at rest
 * it exists only as ciphertext under a non-exportable hardware key that requires an unlocked device.
 * A Keystore key whose KeyInfo reports SOFTWARE security level is rejected.
 */
object AndroidKeystoreIdentity {
    private const val TAG = "ZcpIdentity"
    private const val PROVIDER = "AndroidKeyStore"
    private const val NATIVE_ALIAS = "zcp.identity.ed25519.v1"
    private const val SEAL_ALIAS = "zcp.identity.seal.v1"
    private const val SEALED_FILE = "identity/ed25519.sealed"

    /** Unlocked-device binding only makes sense (and only works everywhere) with a secure lock screen. */
    @Volatile private var deviceSecure = false

    fun loadOrCreate(context: Context): IdentitySigner {
        deviceSecure = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure ?: false
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        val sealedFile = File(context.noBackupFilesDir, SEALED_FILE)

        if (ks.containsAlias(NATIVE_ALIAS)) {
            nativeSigner(ks)?.let { return it }
            ks.deleteEntry(NATIVE_ALIAS)
        }
        if (sealedFile.exists() && ks.containsAlias(SEAL_ALIAS)) {
            sealedSigner(ks, sealedFile)?.let { return it }
            throw CryptoError.HardwareKeystoreFailure("sealed identity exists but cannot be unsealed; refusing to silently rotate identity")
        }
        for (strongBox in listOf(true, false)) {
            if (generateNative(strongBox)) {
                nativeSigner(ks)?.let { return it }
                ks.deleteEntry(NATIVE_ALIAS)
            }
        }
        return createSealed(context, ks, sealedFile)
    }

    // ------------------------------------------------------------------ native Ed25519

    private fun generateNative(strongBox: Boolean): Boolean = try {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        kpg.initialize(
            KeyGenParameterSpec.Builder(NATIVE_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
                .setDigests(KeyProperties.DIGEST_NONE)
                .setIsStrongBoxBacked(strongBox)
                .build(),
        )
        kpg.generateKeyPair()
        true
    } catch (e: StrongBoxUnavailableException) {
        false
    } catch (e: ProviderException) {
        Log.i(TAG, "native Ed25519 unavailable (strongBox=$strongBox): ${e.message}")
        false
    } catch (e: java.security.GeneralSecurityException) {
        Log.i(TAG, "native Ed25519 unsupported: ${e.message}")
        false
    }

    private fun nativeSigner(ks: KeyStore): IdentitySigner? = try {
        buildNativeSigner(ks)
    } catch (e: Exception) {
        // Any Keystore quirk on this build means "native Ed25519 not usable here": the caller deletes the
        // alias and falls back to the sealed identity instead of crashing the app at start-up.
        Log.w(TAG, "native Ed25519 identity unusable: ${e.javaClass.simpleName}: ${e.message}")
        null
    }

    private fun buildNativeSigner(ks: KeyStore): IdentitySigner? {
        // Not KeyStore.getEntry(): on Android 13/14 the Keystore reports different algorithm names for the
        // Ed25519 private key and for its certificate's public key, and the PrivateKeyEntry constructor
        // rejects that with IllegalArgumentException (seen on the API 34 emulator). Read the parts separately.
        val priv = ks.getKey(NATIVE_ALIAS, null) as? PrivateKey ?: return null
        val spki = ks.getCertificate(NATIVE_ALIAS)?.publicKey?.encoded ?: return null
        if (spki.size != 44 || !spki.copyOfRange(0, 12).contentEquals(ED25519_SPKI_PREFIX)) return null
        val raw = spki.copyOfRange(12, 44)
        val level = when (securityLevel(priv)) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> IdentitySecurityLevel.STRONGBOX_NATIVE
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> IdentitySecurityLevel.TEE_NATIVE
            else -> return null
        }
        val signer = object : IdentitySigner {
            override val publicKey: ByteArray get() = raw.copyOf()
            override val securityLevel = level
            override fun sign(message: ByteArray): ByteArray = try {
                Signature.getInstance("Ed25519").run {
                    initSign(priv)
                    update(message)
                    sign()
                }
            } catch (e: java.security.GeneralSecurityException) {
                throw CryptoError.HardwareKeystoreFailure("Keystore Ed25519 signing failed", e)
            }
        }
        return if (selfTest(signer)) signer else null
    }

    private fun securityLevel(key: PrivateKey): Int {
        // Keystore Ed25519 keys report algorithm "EdDSA"/"Ed25519" on some builds; the Keystore
        // KeyFactory is registered under "EC" for them, so try both.
        for (alg in listOf(key.algorithm, KeyProperties.KEY_ALGORITHM_EC)) {
            try {
                return KeyFactory.getInstance(alg, PROVIDER).getKeySpec(key, KeyInfo::class.java).securityLevel
            } catch (e: Exception) {
                // try the next algorithm name
            }
        }
        return KeyProperties.SECURITY_LEVEL_UNKNOWN
    }

    // ------------------------------------------------------------------ sealed fallback

    private fun sealKey(ks: KeyStore): SecretKey? = (ks.getEntry(SEAL_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey

    private fun generateSealKey(strongBox: Boolean): Boolean = try {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(SEAL_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .setUnlockedDeviceRequired(deviceSecure)
                .setIsStrongBoxBacked(strongBox)
                .build(),
        )
        kg.generateKey()
        true
    } catch (e: StrongBoxUnavailableException) {
        false
    } catch (e: ProviderException) {
        false
    }

    private fun createSealed(context: Context, ks: KeyStore, file: File): IdentitySigner {
        val strongBox = generateSealKey(true) || run { if (ks.containsAlias(SEAL_ALIAS)) ks.deleteEntry(SEAL_ALIAS); false }
        if (!strongBox && !generateSealKey(false)) throw CryptoError.HardwareKeystoreFailure("no hardware-backed AES key available")
        val key = sealKey(ks) ?: throw CryptoError.HardwareKeystoreFailure("seal key missing after generation")
        val seed = ByteArray(Ed25519.SECRET_KEY_SIZE)
        Ed25519.generatePrivateKey(CryptoEngine.secureRandom, seed)
        val pub = ByteArray(Ed25519.PUBLIC_KEY_SIZE).also { Ed25519.generatePublicKey(seed, 0, it, 0) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(AAD + pub)
        val ct = cipher.doFinal(seed)
        seed.zeroize()
        val iv = cipher.iv
        require(iv.size == 12)
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(byteArrayOf(1) + pub + iv + ct)
        if (!tmp.renameTo(file)) throw CryptoError.HardwareKeystoreFailure("could not persist sealed identity")
        return sealedSigner(ks, file) ?: throw CryptoError.HardwareKeystoreFailure("freshly sealed identity failed self-test")
    }

    private fun sealedSigner(ks: KeyStore, file: File): IdentitySigner? {
        val key = sealKey(ks) ?: return null
        val blob = file.readBytes()
        if (blob.size != 1 + 32 + 12 + 32 + 16 || blob[0] != 1.toByte()) return null
        val pub = blob.copyOfRange(1, 33)
        val iv = blob.copyOfRange(33, 45)
        val ct = blob.copyOfRange(45, blob.size)
        val level = when (securityLevelOfSecret(key)) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> IdentitySecurityLevel.SOFTWARE_SEALED_STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> IdentitySecurityLevel.SOFTWARE_SEALED_TEE
            else -> IdentitySecurityLevel.SOFTWARE_SEALED_SOFTWARE
        }
        val signer = object : IdentitySigner {
            override val publicKey: ByteArray get() = pub.copyOf()
            override val securityLevel = level
            override fun sign(message: ByteArray): ByteArray {
                val seed = try {
                    Cipher.getInstance("AES/GCM/NoPadding").run {
                        init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                        updateAAD(AAD + pub)
                        doFinal(ct)
                    }
                } catch (e: java.security.GeneralSecurityException) {
                    throw CryptoError.HardwareKeystoreFailure("identity unseal failed (device locked?)", e)
                }
                return SoftwareEd25519Signer.fromSeed(SecretBytes.adopt(seed), level).use { s ->
                    check(s.publicKey.contentEquals(pub)) { "unsealed seed does not match stored public key" }
                    s.sign(message)
                }
            }
        }
        return if (selfTest(signer)) signer else null
    }

    private fun securityLevelOfSecret(key: SecretKey): Int = try {
        val f = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
        (f.getKeySpec(key, KeyInfo::class.java) as KeyInfo).securityLevel
    } catch (e: Exception) {
        KeyProperties.SECURITY_LEVEL_UNKNOWN
    }

    private fun selfTest(signer: IdentitySigner): Boolean = try {
        val probe = CryptoEngine.randomBytes(32)
        CryptoEngine.ed25519Verify(signer.publicKey, probe, signer.sign(probe))
    } catch (e: Exception) {
        Log.w(TAG, "identity self-test failed: ${e.message}")
        false
    }

    private val AAD = "ZCP1-IDENTITY-SEAL-v1".toByteArray()

    /** DER SubjectPublicKeyInfo header for Ed25519 (OID 1.3.101.112), followed by the 32-byte key. */
    private val ED25519_SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    )
}

/**
 * Small secret vault (e.g. the token for your own model server). AES-256-GCM under a TEE key that requires an
 * unlocked device; ciphertext lives in noBackupFilesDir so it never reaches cloud backup.
 */
class KeystoreSecretVault(context: Context) {
    private val deviceSecure = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure ?: false
    private val dir = File(context.noBackupFilesDir, "vault").apply { mkdirs() }
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(): SecretKey {
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUnlockedDeviceRequired(deviceSecure)
                .build(),
        )
        return kg.generateKey()
    }

    @Synchronized
    fun put(name: String, value: String) {
        require(NAME.matches(name))
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        c.updateAAD(name.toByteArray())
        val plain = value.toByteArray(Charsets.UTF_8)
        val ct = c.doFinal(plain)
        plain.zeroize()
        val f = File(dir, "$name.bin")
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(c.iv + ct)
        tmp.renameTo(f)
    }

    @Synchronized
    fun get(name: String): String? {
        require(NAME.matches(name))
        val f = File(dir, "$name.bin")
        if (!f.exists()) return null
        val blob = f.readBytes()
        if (blob.size < 12 + 16) return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
            c.updateAAD(name.toByteArray())
            val plain = c.doFinal(blob, 12, blob.size - 12)
            String(plain, Charsets.UTF_8).also { plain.zeroize() }
        } catch (e: java.security.GeneralSecurityException) {
            null
        }
    }

    @Synchronized
    fun delete(name: String) {
        require(NAME.matches(name))
        File(dir, "$name.bin").delete()
    }

    companion object {
        private const val ALIAS = "zcp.vault.v1"
        private val NAME = Regex("^[a-z0-9_]{1,32}$")
    }
}
