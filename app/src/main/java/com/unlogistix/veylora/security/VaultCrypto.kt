package com.unlogistix.veylora.security

import android.content.Context
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Local vault-key protection.
 *
 * The master password is never persisted. PBKDF2 derives a wrapping key which
 * protects a randomly generated 256-bit vault key using AES-256-GCM.
 */
object VaultCrypto {
    private const val PREFS_NAME = "veylora_vault_metadata_v1"
    private const val FORMAT_VERSION = 1
    private const val KDF_ITERATIONS = 600_000
    private const val KEY_BITS = 256
    private const val SALT_BYTES = 16
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = 128

    private const val KEY_VERSION = "format_version"
    private const val KEY_ITERATIONS = "kdf_iterations"
    private const val KEY_SALT = "kdf_salt"
    private const val KEY_NONCE = "wrap_nonce"
    private const val KEY_WRAPPED = "wrapped_vault_key"

    private val random = SecureRandom()

    fun isInitialized(context: Context): Boolean =
        preferences(context).contains(KEY_WRAPPED)

    @Synchronized
    @Throws(GeneralSecurityException::class)
    fun create(context: Context, masterPassword: CharArray) {
        var salt: ByteArray? = null
        var nonce: ByteArray? = null
        var vaultKey: ByteArray? = null
        var wrappingKey: ByteArray? = null
        try {
            val prefs = preferences(context)
            check(!prefs.contains(KEY_WRAPPED)) { "Vault is already initialized." }

            val generatedSalt = ByteArray(SALT_BYTES).also(random::nextBytes)
            val generatedNonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
            val generatedVaultKey = ByteArray(KEY_BITS / 8).also(random::nextBytes)
            salt = generatedSalt
            nonce = generatedNonce
            vaultKey = generatedVaultKey

            wrappingKey = deriveKey(masterPassword, generatedSalt, KDF_ITERATIONS)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(wrappingKey, "AES"),
                GCMParameterSpec(TAG_BITS, generatedNonce)
            )
            cipher.updateAAD(associatedData(KDF_ITERATIONS))
            val wrappedKey = cipher.doFinal(generatedVaultKey)
            try {
                val saved = prefs.edit()
                    .putInt(KEY_VERSION, FORMAT_VERSION)
                    .putInt(KEY_ITERATIONS, KDF_ITERATIONS)
                    .putString(KEY_SALT, Base64.encodeToString(generatedSalt, Base64.NO_WRAP))
                    .putString(KEY_NONCE, Base64.encodeToString(generatedNonce, Base64.NO_WRAP))
                    .putString(KEY_WRAPPED, Base64.encodeToString(wrappedKey, Base64.NO_WRAP))
                    .commit()

                if (!saved) throw GeneralSecurityException("Could not save vault metadata.")
                VaultSession.unlockWith(generatedVaultKey)
            } finally {
                wrappedKey.fill(0)
            }
        } finally {
            masterPassword.fill('\u0000')
            wrappingKey?.fill(0)
            salt?.fill(0)
            nonce?.fill(0)
            vaultKey?.fill(0)
        }
    }

    @Synchronized
    @Throws(GeneralSecurityException::class)
    fun unlock(context: Context, masterPassword: CharArray) {
        var salt: ByteArray? = null
        var nonce: ByteArray? = null
        var wrappedKey: ByteArray? = null
        var wrappingKey: ByteArray? = null
        var vaultKey: ByteArray? = null
        try {
            val prefs = preferences(context)
            check(prefs.contains(KEY_WRAPPED)) { "Vault has not been initialized." }

            val version = prefs.getInt(KEY_VERSION, -1)
            val iterations = prefs.getInt(KEY_ITERATIONS, -1)
            if (version != FORMAT_VERSION || iterations !in 100_000..2_000_000) {
                throw GeneralSecurityException("Vault metadata is invalid or unsupported.")
            }

            val decodedSalt = decode(prefs.getString(KEY_SALT, null), SALT_BYTES)
            salt = decodedSalt
            val decodedNonce = decode(prefs.getString(KEY_NONCE, null), NONCE_BYTES)
            nonce = decodedNonce
            val decodedWrappedKey = decode(prefs.getString(KEY_WRAPPED, null), 32 + TAG_BITS / 8)
            wrappedKey = decodedWrappedKey

            try {
                wrappingKey = deriveKey(masterPassword, decodedSalt, iterations)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(wrappingKey, "AES"),
                    GCMParameterSpec(TAG_BITS, decodedNonce)
                )
                cipher.updateAAD(associatedData(iterations))
                vaultKey = cipher.doFinal(decodedWrappedKey)
                if (vaultKey.size != KEY_BITS / 8) {
                    throw GeneralSecurityException("Vault key has an invalid length.")
                }
                VaultSession.unlockWith(vaultKey)
            } catch (badTag: AEADBadTagException) {
                throw InvalidMasterPasswordException()
            }
        } finally {
            masterPassword.fill('\u0000')
            wrappingKey?.fill(0)
            vaultKey?.fill(0)
            salt?.fill(0)
            nonce?.fill(0)
            wrappedKey?.fill(0)
        }
    }

    @Synchronized
    @Throws(GeneralSecurityException::class)
    fun changeMasterPassword(context: Context, currentPassword: CharArray, newPassword: CharArray) {
        var vaultKey: ByteArray? = null
        var salt: ByteArray? = null
        var nonce: ByteArray? = null
        var wrappingKey: ByteArray? = null
        var wrappedKey: ByteArray? = null
        try {
            require(newPassword.size >= 10) { "New master password must contain at least 10 characters." }
            // Verify the current password before changing any persisted metadata.
            unlock(context, currentPassword)
            vaultKey = VaultSession.keyCopy()
            salt = ByteArray(SALT_BYTES).also(random::nextBytes)
            nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
            wrappingKey = deriveKey(newPassword, salt, KDF_ITERATIONS)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrappingKey, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(associatedData(KDF_ITERATIONS))
            wrappedKey = cipher.doFinal(vaultKey)

            val saved = preferences(context).edit()
                .putInt(KEY_VERSION, FORMAT_VERSION)
                .putInt(KEY_ITERATIONS, KDF_ITERATIONS)
                .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                .putString(KEY_NONCE, Base64.encodeToString(nonce, Base64.NO_WRAP))
                .putString(KEY_WRAPPED, Base64.encodeToString(wrappedKey, Base64.NO_WRAP))
                .commit()
            if (!saved) throw GeneralSecurityException("Could not save the new master password.")
        } finally {
            currentPassword.fill('\u0000')
            newPassword.fill('\u0000')
            vaultKey?.fill(0)
            salt?.fill(0)
            nonce?.fill(0)
            wrappingKey?.fill(0)
            wrappedKey?.fill(0)
        }
    }

    private fun deriveKey(password: CharArray, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(password, salt, iterations, KEY_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec)
                .encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun associatedData(iterations: Int): ByteArray =
        "VEYlora|vault-key|v1|PBKDF2-HMAC-SHA256|$iterations"
            .toByteArray(StandardCharsets.UTF_8)

    private fun decode(value: String?, expectedMinimum: Int): ByteArray {
        if (value.isNullOrBlank()) throw GeneralSecurityException("Vault metadata is incomplete.")
        val decoded = try {
            Base64.decode(value, Base64.NO_WRAP)
        } catch (error: IllegalArgumentException) {
            throw GeneralSecurityException("Vault metadata is corrupted.", error)
        }
        if (decoded.size < expectedMinimum) {
            decoded.fill(0)
            throw GeneralSecurityException("Vault metadata is corrupted.")
        }
        return decoded
    }

    private fun preferences(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}

class InvalidMasterPasswordException : GeneralSecurityException(
    "The master password is incorrect."
)

/**
 * Holds the unwrapped vault key only in process memory. Call lock() when the
 * app leaves the foreground. Call keyCopy() only from the encrypted repository.
 */
object VaultSession {
    private var vaultKey: ByteArray? = null

    @Synchronized
    fun isUnlocked(): Boolean = vaultKey != null

    @Synchronized
    internal fun unlockWith(key: ByteArray) {
        vaultKey?.fill(0)
        vaultKey = key.copyOf()
    }

    @Synchronized
    fun keyCopy(): ByteArray {
        return vaultKey?.copyOf()
            ?: throw IllegalStateException("Vault is locked.")
    }

    @Synchronized
    fun lock() {
        vaultKey?.fill(0)
        vaultKey = null
    }
}
