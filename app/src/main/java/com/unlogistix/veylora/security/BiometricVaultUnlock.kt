package com.unlogistix.veylora.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Optional biometric convenience unlock.
 *
 * The Android Keystore key requires strong biometric authentication for each
 * cryptographic operation. The master-password path remains available.
 */
object BiometricVaultUnlock {
    private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "veylora_biometric_v1"
    private const val PREFS_NAME = "veylora_biometric_metadata_v1"
    private const val KEY_IV = "wrapped_key_iv"
    private const val KEY_CIPHERTEXT = "wrapped_key_ciphertext"
    private const val TAG_BITS = 128

    fun isEnabled(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.contains(KEY_IV) && prefs.contains(KEY_CIPHERTEXT) && keyExists()
    }

    @Synchronized
    fun prepareEnrollmentCipher(): Cipher {
        val store = loadKeyStore()
        if (store.containsAlias(KEY_ALIAS)) {
            store.deleteEntry(KEY_ALIAS)
        }

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEY_STORE
        )
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        generator.init(builder.build())
        generator.generateKey()
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, getSecretKey())
        }
    }

    @Synchronized
    fun finishEnrollment(context: Context, authenticatedCipher: Cipher) {
        val key = VaultSession.keyCopy()
        try {
            val encrypted = authenticatedCipher.doFinal(key)
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val saved = prefs.edit()
                .putString(KEY_IV, Base64.encodeToString(authenticatedCipher.iv, Base64.NO_WRAP))
                .putString(KEY_CIPHERTEXT, Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .commit()
            encrypted.fill(0)
            if (!saved) throw IllegalStateException("Could not save biometric unlock data.")
        } finally {
            key.fill(0)
        }
    }

    @Synchronized
    fun prepareUnlock(context: Context): Pair<Cipher, ByteArray> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val iv = decode(prefs.getString(KEY_IV, null))
        val ciphertext = decode(prefs.getString(KEY_CIPHERTEXT, null))
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), GCMParameterSpec(TAG_BITS, iv))
            return cipher to ciphertext
        } finally {
            iv.fill(0)
        }
    }

    @Synchronized
    fun finishUnlock(cipher: Cipher, ciphertext: ByteArray) {
        var key: ByteArray? = null
        try {
            key = cipher.doFinal(ciphertext)
            if (key.size != 32) throw IllegalStateException("Invalid vault key.")
            VaultSession.unlockWith(key)
        } finally {
            key?.fill(0)
            ciphertext.fill(0)
        }
    }

    @Synchronized
    fun disable(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().clear().commit()
        val store = loadKeyStore()
        if (store.containsAlias(KEY_ALIAS)) store.deleteEntry(KEY_ALIAS)
    }

    private fun keyExists(): Boolean = loadKeyStore().containsAlias(KEY_ALIAS)

    private fun getSecretKey(): SecretKey =
        loadKeyStore().getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("Biometric key is unavailable. Use the master password.")

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private fun decode(value: String?): ByteArray {
        if (value.isNullOrBlank()) throw IllegalStateException("Biometric unlock is not configured.")
        return try {
            Base64.decode(value, Base64.NO_WRAP)
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException("Biometric unlock data is corrupted.", error)
        }
    }
}
