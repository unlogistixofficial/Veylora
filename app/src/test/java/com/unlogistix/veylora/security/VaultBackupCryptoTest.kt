package com.unlogistix.veylora.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.GeneralSecurityException

class VaultBackupCryptoTest {
    @Test
    fun encryptDecryptRoundTripPreservesPayloadAndClearsPasswords() {
        val payload = "Veylora portable backup test payload".toByteArray(Charsets.UTF_8)
        val encryptionPassword = "Correct-Horse-Backup-2026".toCharArray()
        val envelope = VaultBackupCrypto.encrypt(payload, encryptionPassword)

        assertTrue(encryptionPassword.all { it == '\u0000' })
        assertTrue(envelope.size > payload.size)

        val decryptionPassword = "Correct-Horse-Backup-2026".toCharArray()
        val restored = VaultBackupCrypto.decrypt(envelope, decryptionPassword)
        try {
            assertArrayEquals(payload, restored)
            assertTrue(decryptionPassword.all { it == '\u0000' })
        } finally {
            payload.fill(0)
            envelope.fill(0)
            restored.fill(0)
        }
    }

    @Test
    fun wrongPasswordAndModifiedEnvelopeAreRejected() {
        val payload = "authenticated backup data".toByteArray(Charsets.UTF_8)
        val envelope = VaultBackupCrypto.encrypt(
            payload,
            "Correct-Horse-Backup-2026".toCharArray()
        )
        try {
            val wrongPassword = "Incorrect-Backup-Password".toCharArray()
            var wrongPasswordRejected = false
            try {
                VaultBackupCrypto.decrypt(envelope, wrongPassword)
            } catch (_: GeneralSecurityException) {
                wrongPasswordRejected = true
            }
            assertTrue(wrongPasswordRejected)
            assertTrue(wrongPassword.all { it == '\u0000' })

            val tampered = envelope.copyOf()
            tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()
            val password = "Correct-Horse-Backup-2026".toCharArray()
            var tamperingRejected = false
            try {
                VaultBackupCrypto.decrypt(tampered, password)
            } catch (_: GeneralSecurityException) {
                tamperingRejected = true
            } finally {
                tampered.fill(0)
            }
            assertTrue(tamperingRejected)
            assertTrue(password.all { it == '\u0000' })
        } finally {
            payload.fill(0)
            envelope.fill(0)
        }
    }

    @Test
    fun invalidPayloadAndShortPasswordAreRejectedAndCleared() {
        val invalidPayloadPassword = "Correct-Horse-Backup-2026".toCharArray()
        var invalidPayloadRejected = false
        try {
            VaultBackupCrypto.encrypt(ByteArray(0), invalidPayloadPassword)
        } catch (_: IllegalArgumentException) {
            invalidPayloadRejected = true
        }
        assertTrue(invalidPayloadRejected)
        assertTrue(invalidPayloadPassword.all { it == '\u0000' })

        val shortPassword = "too-short".toCharArray()
        var shortPasswordRejected = false
        try {
            VaultBackupCrypto.encrypt(byteArrayOf(1), shortPassword)
        } catch (_: IllegalArgumentException) {
            shortPasswordRejected = true
        }
        assertTrue(shortPasswordRejected)
        assertTrue(shortPassword.all { it == '\u0000' })
    }
}
