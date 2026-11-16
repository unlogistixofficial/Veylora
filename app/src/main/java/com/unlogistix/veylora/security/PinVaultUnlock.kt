package com.unlogistix.veylora.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Device-local PIN convenience unlock.
 *
 * The PIN is never stored. A non-exportable Android Keystore HMAC key derives
 * the AES wrapping key, so copied preferences alone cannot be used for an
 * offline PIN-guessing attack. The five-attempt counter is app-local state and
 * is not tamper-proof on a rooted/compromised device. Master password remains
 * the recovery path.
 */
enum class PinUnlockResult { SUCCESS, WRONG_PIN, LOCKED_OUT }

object PinVaultUnlock {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val HMAC_ALIAS = "veylora_pin_hmac_v1"
    private const val PREFS = "veylora_pin_metadata_v1"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_IV = "wrapped_key_iv"
    private const val KEY_CIPHERTEXT = "wrapped_key_ciphertext"
    private const val KEY_ATTEMPTS = "failed_attempts"
    private const val KEY_LOCKED_OUT = "locked_out"
    private const val MAX_ATTEMPTS = 5
    private const val TAG_BITS = 128
    private const val AAD = "VEYlora|pin-wrapped-vault-key|v1"
    private const val KDF_CONTEXT = "VEYlora|pin-kdf|v1|"

    @Synchronized
    fun isEnabled(context: Context): Boolean {
        val prefs = preferences(context)
        return prefs.getBoolean(KEY_ENABLED, false) &&
            prefs.contains(KEY_IV) && prefs.contains(KEY_CIPHERTEXT) &&
            keyExists()
    }

    fun wasLockedOut(context: Context): Boolean =
        preferences(context).getBoolean(KEY_LOCKED_OUT, false)

    @Synchronized
    fun enable(context: Context, pin: CharArray) {
        try {
            validatePin(pin)
            check(VaultSession.isUnlocked()) { "Unlock the vault before setting a PIN." }
        } catch (error: Exception) {
            pin.fill('\u0000')
            throw error
        }
        val vaultKey = try {
            VaultSession.keyCopy()
        } catch (error: Exception) {
            pin.fill('\u0000')
            throw error
        }
        var wrappingKey: ByteArray? = null
        try {
            deleteHmacKey()
            val hmacKey = generateHmacKey()
            wrappingKey = deriveWrappingKey(hmacKey, pin)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrappingKey, "AES"))
            cipher.updateAAD(AAD.toByteArray(StandardCharsets.UTF_8))
            val ciphertext = cipher.doFinal(vaultKey)
            val saved = preferences(context).edit()
                .putBoolean(KEY_ENABLED, true)
                .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .putString(KEY_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putInt(KEY_ATTEMPTS, 0)
                .putBoolean(KEY_LOCKED_OUT, false)
                .commit()
            ciphertext.fill(0)
            if (!saved) throw IllegalStateException("Could not save PIN unlock data.")
        } catch (error: Exception) {
            preferences(context).edit()
                .remove(KEY_ENABLED).remove(KEY_IV).remove(KEY_CIPHERTEXT)
                .putInt(KEY_ATTEMPTS, 0).commit()
            deleteHmacKey()
            throw error
        } finally {
            pin.fill('\u0000')
            vaultKey.fill(0)
            wrappingKey?.fill(0)
        }
    }

    @Synchronized
    fun unlock(context: Context, pin: CharArray): PinUnlockResult {
        val prefs = preferences(context)
        try {
            if (prefs.getBoolean(KEY_LOCKED_OUT, false) ||
                prefs.getInt(KEY_ATTEMPTS, 0) >= MAX_ATTEMPTS ||
                !isEnabled(context)
            ) return PinUnlockResult.LOCKED_OUT

            val iv = decode(prefs.getString(KEY_IV, null))
            val ciphertext = decode(prefs.getString(KEY_CIPHERTEXT, null))
            var wrappingKey: ByteArray? = null
            var vaultKey: ByteArray? = null
            try {
                val hmacKey = loadHmacKey()
                wrappingKey = deriveWrappingKey(hmacKey, pin)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(wrappingKey, "AES"), GCMParameterSpec(TAG_BITS, iv))
                cipher.updateAAD(AAD.toByteArray(StandardCharsets.UTF_8))
                vaultKey = cipher.doFinal(ciphertext)
                if (vaultKey.size != 32) throw IllegalStateException("Invalid wrapped vault key.")
                VaultSession.unlockWith(vaultKey)
                prefs.edit().putInt(KEY_ATTEMPTS, 0).commit()
                return PinUnlockResult.SUCCESS
            } catch (_: AEADBadTagException) {
                val attempts = prefs.getInt(KEY_ATTEMPTS, 0) + 1
                if (attempts >= MAX_ATTEMPTS) {
                    lockOut(context)
                    return PinUnlockResult.LOCKED_OUT
                }
                prefs.edit().putInt(KEY_ATTEMPTS, attempts).commit()
                return PinUnlockResult.WRONG_PIN
            } finally {
                iv.fill(0)
                ciphertext.fill(0)
                wrappingKey?.fill(0)
                vaultKey?.fill(0)
            }
        } finally {
            pin.fill('\u0000')
        }
    }

    @Synchronized
    fun disable(context: Context) {
        preferences(context).edit()
            .remove(KEY_ENABLED).remove(KEY_IV).remove(KEY_CIPHERTEXT)
            .putInt(KEY_ATTEMPTS, 0)
            .putBoolean(KEY_LOCKED_OUT, false)
            .commit()
        deleteHmacKey()
    }

    private fun lockOut(context: Context) {
        preferences(context).edit()
            .remove(KEY_ENABLED).remove(KEY_IV).remove(KEY_CIPHERTEXT)
            .putInt(KEY_ATTEMPTS, MAX_ATTEMPTS)
            .putBoolean(KEY_LOCKED_OUT, true)
            .commit()
        deleteHmacKey()
    }

    private fun validatePin(pin: CharArray) {
        require(pin.size in 6..12 && pin.all { it in '0'..'9' }) {
            "PIN must contain 6–12 digits."
        }
    }

    private fun generateHmacKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                HMAC_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).setDigests(KeyProperties.DIGEST_SHA256).build()
        )
        return generator.generateKey()
    }

    private fun deriveWrappingKey(key: SecretKey, pin: CharArray): ByteArray {
        // PINs are restricted to ASCII digits, so encode directly without
        // creating an immutable String copy that cannot be reliably cleared.
        val pinBytes = ByteArray(pin.size) { index -> pin[index].code.toByte() }
        return try {
            Mac.getInstance("HmacSHA256").run {
                init(key)
                update(KDF_CONTEXT.toByteArray(StandardCharsets.UTF_8))
                doFinal(pinBytes)
            }
        } finally {
            pinBytes.fill(0)
        }
    }

    private fun loadHmacKey(): SecretKey =
        keyStore().getKey(HMAC_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("PIN Keystore key is unavailable. Use your master password.")

    private fun keyExists(): Boolean = try {
        keyStore().containsAlias(HMAC_ALIAS)
    } catch (_: Exception) { false }

    private fun deleteHmacKey() {
        val store = keyStore()
        if (store.containsAlias(HMAC_ALIAS)) store.deleteEntry(HMAC_ALIAS)
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun decode(value: String?): ByteArray {
        if (value.isNullOrBlank()) throw IllegalStateException("PIN unlock metadata is missing.")
        return try {
            Base64.decode(value, Base64.NO_WRAP).also {
                if (it.size < 12) {
                    it.fill(0)
                    throw IllegalStateException("PIN unlock metadata is corrupted.")
                }
            }
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException("PIN unlock metadata is corrupted.", error)
        }
    }

    private fun preferences(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
