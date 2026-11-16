package com.unlogistix.veylora.security

import java.nio.ByteBuffer
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
 * Password-based encryption envelope for portable Veylora backup payloads.
 *
 * The payload passed to this class must already be a complete backup snapshot.
 * This class only protects/unprotects its bytes; it does not read vault files.
 */
object VaultBackupCrypto {
    private const val VERSION = 1
    private const val SALT_BYTES = 16
    private const val NONCE_BYTES = 12
    private const val KEY_BITS = 256
    private const val TAG_BITS = 128
    private const val ITERATIONS = 600_000
    private const val MIN_PASSWORD_LENGTH = 12
    private const val MAX_PAYLOAD_BYTES = 100 * 1024 * 1024
    private const val HEADER_BYTES = 8 + 1 + SALT_BYTES + NONCE_BYTES
    private val MAGIC = byteArrayOf(0x56, 0x45, 0x59, 0x42, 0x41, 0x4b, 0x31, 0x00)
    private val random = SecureRandom()

    @JvmStatic
    @Synchronized
    fun encrypt(payload: ByteArray, password: CharArray): ByteArray {
        validateInputs(payload, password)
        val salt = ByteArray(SALT_BYTES).also(random::nextBytes)
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        var key: ByteArray? = null
        var ciphertext: ByteArray? = null
        try {
            key = deriveKey(password, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(associatedData())
            ciphertext = cipher.doFinal(payload)
            return ByteBuffer.allocate(HEADER_BYTES + ciphertext.size)
                .put(MAGIC)
                .put(VERSION.toByte())
                .put(salt)
                .put(nonce)
                .put(ciphertext)
                .array()
        } finally {
            password.fill(0.toChar())
            salt.fill(0)
            nonce.fill(0)
            key?.fill(0)
            ciphertext?.fill(0)
        }
    }

    @JvmStatic
    @Synchronized
    fun decrypt(envelope: ByteArray, password: CharArray): ByteArray {
        if (password.size < MIN_PASSWORD_LENGTH) {
            password.fill(0.toChar())
            throw IllegalArgumentException("Backup password must contain at least $MIN_PASSWORD_LENGTH characters.")
        }
        if (envelope.size < HEADER_BYTES + 16 || envelope.size > MAX_PAYLOAD_BYTES + HEADER_BYTES + 16) {
            password.fill(0.toChar())
            throw GeneralSecurityException("Backup file size is invalid.")
        }

        var salt: ByteArray? = null
        var nonce: ByteArray? = null
        var ciphertext: ByteArray? = null
        var key: ByteArray? = null
        try {
            val header = ByteBuffer.wrap(envelope)
            val magic = ByteArray(MAGIC.size).also(header::get)
            if (!magic.contentEquals(MAGIC) || header.get().toInt() != VERSION) {
                throw GeneralSecurityException("This is not a supported Veylora backup.")
            }
            salt = ByteArray(SALT_BYTES).also(header::get)
            nonce = ByteArray(NONCE_BYTES).also(header::get)
            ciphertext = ByteArray(header.remaining()).also(header::get)
            if (ciphertext.size - 16 > MAX_PAYLOAD_BYTES) {
                throw GeneralSecurityException("Backup payload exceeds the supported size.")
            }
            key = deriveKey(password, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(associatedData())
            return try {
                cipher.doFinal(ciphertext)
            } catch (error: AEADBadTagException) {
                throw GeneralSecurityException("Backup password is incorrect or the file has been modified.", error)
            }
        } finally {
            password.fill(0.toChar())
            salt?.fill(0)
            nonce?.fill(0)
            ciphertext?.fill(0)
            key?.fill(0)
        }
    }

    private fun validateInputs(payload: ByteArray, password: CharArray) {
        require(payload.isNotEmpty() && payload.size <= MAX_PAYLOAD_BYTES) {
            "Backup payload must be between 1 byte and 100 MB."
        }
        require(password.size >= MIN_PASSWORD_LENGTH) {
            password.fill(0.toChar())
            "Backup password must contain at least $MIN_PASSWORD_LENGTH characters."
        }
    }

    private fun deriveKey(password: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password, salt, ITERATIONS, KEY_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec)
                .encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun associatedData(): ByteArray =
        "VEYlora|portable-backup|AES-256-GCM|PBKDF2-SHA256|v1".toByteArray(StandardCharsets.UTF_8)
}
