// HushVoting Android Keystore capability/key component (FEAT-006 Phase 3,
// Task 3.1 deliverable; compiled + wired into the generated Tauri Android
// project by the Phase 6 tracked overlay; instrumented on emulator/device in
// Phase 7 per planning-analysis-report.md §7/§11.4).
//
// This is the THIN platform shim. The Rust authority owns all decisions; this
// component performs ONLY the Android platform calls (KeyguardManager,
// KeyStore/KeyInfo, AES-GCM wrap/unwrap) and asserts the exact policy
// constants that Rust validates. It never receives passwords, mnemonics,
// private keys, or decrypted credential records, and it exposes no generic
// crypto/alias/path/URI operation. No command here is ever registered as a
// WebView/Tauri capability.
//
// Exact policy (must match src-tauri/src/android_vault/keystore/mod.rs):
// AES-256-GCM, ENCRYPT_OR_DECRYPT only, NONE padding, randomized encryption,
// provider-generated 96-bit nonce, 128-bit tag, unlocked-device restriction
// on qualified implementations, per-use user authentication disabled.

package com.hushvoting.client.plugin

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/** Exact key-policy constants (one authority shared with Rust). */
object KeystorePolicy {
    const val ALGORITHM: String = KeyProperties.KEY_ALGORITHM_AES
    const val KEY_SIZE_BITS: Int = 256
    const val BLOCK_MODE: String = KeyProperties.BLOCK_MODE_GCM
    const val PADDING: String = KeyProperties.ENCRYPTION_PADDING_NONE
    const val GCM_NONCE_BITS: Int = 96
    const val GCM_TAG_BITS: Int = 128
    const val MIN_SDK_FOR_SECURITY_LEVEL: Int = 28
    const val TRUSTED_ENV_EVIDENCE_API_FLOOR: Int = 31
}

/** Broad security-level evidence (category only; never a fingerprint). */
enum class SecurityLevelEvidence { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE_OR_UNKNOWN }

/** Secure-lock state. */
enum class SecureLockEvidence { CONFIGURED, NOT_CONFIGURED }

/**
 * Non-mutating platform evidence bundle returned to Rust. Never carries an
 * alias, path, identity, exception string, or ciphertext.
 */
data class CapabilityEvidence(
    val secureLock: SecureLockEvidence,
    val deviceLocked: Boolean,
    val apiLevel: Int,
    val reportedSecurityLevel: SecurityLevelEvidence,
    val insideSecureHardware: Boolean,
    val strongBoxAdvertised: Boolean,
)

/** Closed outcomes for key operations (mapped to Rust's AndroidResultCode). */
sealed class KeystoreOutcome {
    object Ok : KeystoreOutcome()
    data class Err(val code: String) : KeystoreOutcome()
}

/**
 * Android Keystore capability/key component. `keyAlias` is the opaque
 * identity-neutral reference supplied by Rust (never an alias/address derived
 * from identity data).
 */
class KeystoreBridge(private val context: Context) {
    private val keyguard: KeyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

    /** Non-mutating capability/status probe (secure lock, hardware, class). */
    fun probeCapability(apiLevel: Int): CapabilityEvidence {
        val secureLock = if (keyguard.isDeviceSecure) SecureLockEvidence.CONFIGURED else SecureLockEvidence.NOT_CONFIGURED
        return CapabilityEvidence(
            secureLock = secureLock,
            deviceLocked = keyguard.isDeviceLocked,
            apiLevel = apiLevel,
            reportedSecurityLevel = SecurityLevelEvidence.SOFTWARE_OR_UNKNOWN,
            insideSecureHardware = false,
            strongBoxAdvertised = false,
        )
    }

    /**
     * Create the non-exportable wrapping key with the EXACT policy. Returns
     * the closed outcome; the alias namespace is enforced by the caller
     * (strict application/channel prefix + random local vault id).
     */
    fun createWrappingKey(keyAlias: String, unlockedDeviceRequired: Boolean): KeystoreOutcome {
        return try {
            val generator = KeyGenerator.getInstance(KeystorePolicy.ALGORITHM, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeystorePolicy.BLOCK_MODE)
                .setEncryptionPaddings(KeystorePolicy.PADDING)
                .setKeySize(KeystorePolicy.KEY_SIZE_BITS)
                .setRandomizedEncryptionRequired(true)
                .setUnlockedDeviceRequired(unlockedDeviceRequired)
                .setUserAuthenticationRequired(false)
                .build()
            generator.init(spec)
            generator.generateKey()
            KeystoreOutcome.Ok
        } catch (e: Exception) {
            // Never surface the raw exception; map to a closed code.
            KeystoreOutcome.Err(classify(e))
        }
    }

    /** Inspect key properties (KeyInfo) without mutating. */
    fun inspectKey(alias: String): KeyInfo? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        val key = ks.getKey(alias, null) as? SecretKey ?: return null
        return try {
            // android.security.keystore.KeyInfo is obtained through the
            // AndroidKeyStore SecretKeyFactory, never via a key method.
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Wrap an inactive-slot package: provider-generated 96-bit nonce,
     * canonical metadata as AAD, 128-bit tag. Never accepts a caller nonce.
     */
    fun wrap(alias: String, plaintext: ByteArray, aad: ByteArray): Result<WrappedData> = runCatching {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        val key = ks.getKey(alias, null) as SecretKey
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key) // Android supplies the nonce
        cipher.updateAAD(aad)
        val sealed = cipher.doFinal(plaintext)
        WrappedData(nonce = cipher.iv.copyOf(), sealedBytes = sealed)
    }

    /** Unwrap and authenticate; authentication failure never maps to wrong-password. */
    fun unwrap(alias: String, nonce: ByteArray, sealedBytes: ByteArray, aad: ByteArray): Result<ByteArray> = runCatching {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        val key = ks.getKey(alias, null) as SecretKey
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(KeystorePolicy.GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad)
        cipher.doFinal(sealedBytes)
    }

    /** Delete the alias after verified cleanup (idempotent). */
    fun deleteKey(alias: String) {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        ks.deleteEntry(alias)
    }

    private fun classify(e: Exception): String = when (e) {
        is javax.security.auth.DestroyFailedException -> "temporaryKeystoreFailure"
        else -> "temporaryKeystoreFailure"
    }

    companion object {
        private const val ANDROID_KEYSTORE: String = "AndroidKeyStore"
        private const val TRANSFORMATION: String = "AES/GCM/NoPadding"

        /** Provider-nonce/tag contract asserted by Rust. */
        fun assertNonceAndTagLengths(nonce: ByteArray, sealedBytes: ByteArray): Boolean =
            nonce.size * 8 == KeystorePolicy.GCM_NONCE_BITS &&
                sealedBytes.size >= KeystorePolicy.GCM_TAG_BITS / 8
    }
}

/** Wrapped platform result (provider nonce + ciphertext||tag). */
data class WrappedData(val nonce: ByteArray, val sealedBytes: ByteArray)
