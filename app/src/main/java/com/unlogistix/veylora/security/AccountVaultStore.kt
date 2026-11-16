package com.unlogistix.veylora.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypted, device-local account storage.
 *
 * All account fields are serialized into one authenticated AES-GCM payload.
 * The encryption key is copied from VaultSession and is never persisted here.
 * The file lives under noBackupFilesDir so Android backup/restore cannot
 * silently move encrypted data without its associated device-local setup.
 */
data class VaultAccount(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val username: String = "",
    val password: String = "",
    val website: String = "",
    val notes: String = "",
    val category: String = "Other",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = createdAt
)

object AccountVaultStore {
    private const val FILE_NAME = "veylora_accounts_v1.bin"
    private const val FORMAT_VERSION = 1
    private const val NONCE_BYTES = 12
    private const val TAG_BITS = 128
    private const val KEY_BYTES = 32
    private const val MAX_FILE_BYTES = 5 * 1024 * 1024
    private const val MAX_ACCOUNTS = 10_000
    private const val MAX_FIELD_LENGTH = 100_000
    private val MAGIC = byteArrayOf(0x56, 0x45, 0x59, 0x4c, 0x4f, 0x52, 0x41, 0x31)
    private val random = SecureRandom()

    @Synchronized
    fun load(context: Context): List<VaultAccount> {
        val file = dataFile(context)
        if (!file.exists()) return emptyList()
        if (!file.isFile || file.length() !in (MAGIC.size + NONCE_BYTES + 16).toLong()..MAX_FILE_BYTES.toLong()) {
            throw GeneralSecurityException("Encrypted account storage has an invalid size.")
        }

        val envelope = FileInputStream(file).use { input ->
            val bytes = ByteArray(file.length().toInt())
            var offset = 0
            while (offset < bytes.size) {
                val count = input.read(bytes, offset, bytes.size - offset)
                if (count < 0) {
                    bytes.fill(0)
                    throw GeneralSecurityException("Encrypted account storage is incomplete.")
                }
                offset += count
            }
            bytes
        }

        var key: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            val headerSize = MAGIC.size + 1 + NONCE_BYTES
            if (envelope.size < headerSize + 16 ||
                !envelope.copyOfRange(0, MAGIC.size).contentEquals(MAGIC) ||
                envelope[MAGIC.size].toInt() != FORMAT_VERSION
            ) {
                throw GeneralSecurityException("Encrypted account storage has an unsupported format.")
            }

            val nonceStart = MAGIC.size + 1
            val nonce = envelope.copyOfRange(nonceStart, nonceStart + NONCE_BYTES)
            val ciphertext = envelope.copyOfRange(nonceStart + NONCE_BYTES, envelope.size)
            try {
                key = VaultSession.keyCopy()
                if (key.size != KEY_BYTES) throw GeneralSecurityException("Vault key has an invalid length.")
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
                cipher.updateAAD(associatedData())
                plaintext = cipher.doFinal(ciphertext)
                return decodeAccounts(plaintext)
            } finally {
                nonce.fill(0)
                ciphertext.fill(0)
            }
        } finally {
            key?.fill(0)
            plaintext?.fill(0)
            envelope.fill(0)
        }
    }

    @Synchronized
    fun save(context: Context, accounts: List<VaultAccount>) {
        require(accounts.size <= MAX_ACCOUNTS) { "Too many accounts." }
        val seenIds = HashSet<String>(accounts.size)
        accounts.forEach { account ->
            validate(account)
            require(seenIds.add(account.id)) { "Duplicate account ID." }
        }

        val json = JSONArray()
        accounts.forEach { account ->
            json.put(
                JSONObject()
                    .put("id", account.id)
                    .put("title", account.title)
                    .put("username", account.username)
                    .put("password", account.password)
                    .put("website", account.website)
                    .put("notes", account.notes)
                    .put("category", account.category)
                    .put("createdAt", account.createdAt)
                    .put("updatedAt", account.updatedAt)
            )
        }

        val plaintext = json.toString().toByteArray(StandardCharsets.UTF_8)
        var key: ByteArray? = null
        var ciphertext: ByteArray? = null
        var nonce: ByteArray? = null
        try {
            if (plaintext.size > MAX_FILE_BYTES - MAGIC.size - 1 - NONCE_BYTES - 16) {
                throw GeneralSecurityException("Account data is too large to store.")
            }
            key = VaultSession.keyCopy()
            if (key.size != KEY_BYTES) throw GeneralSecurityException("Vault key has an invalid length.")
            nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(associatedData())
            ciphertext = cipher.doFinal(plaintext)

            val envelope = ByteBuffer.allocate(MAGIC.size + 1 + NONCE_BYTES + ciphertext.size)
                .put(MAGIC)
                .put(FORMAT_VERSION.toByte())
                .put(nonce)
                .put(ciphertext)
                .array()
            try {
                atomicWrite(context, envelope)
            } finally {
                envelope.fill(0)
            }
        } finally {
            plaintext.fill(0)
            key?.fill(0)
            ciphertext?.fill(0)
            nonce?.fill(0)
        }
    }

    @Synchronized
    fun upsert(context: Context, account: VaultAccount) {
        validate(account)
        val accounts = load(context).toMutableList()
        val index = accounts.indexOfFirst { it.id == account.id }
        val now = System.currentTimeMillis()
        val saved = if (index >= 0) account.copy(createdAt = accounts[index].createdAt, updatedAt = now)
            else account.copy(updatedAt = now)
        if (index >= 0) accounts[index] = saved else accounts.add(0, saved)
        save(context, accounts)
    }

    @Synchronized
    fun delete(context: Context, accountId: String) {
        val accounts = load(context)
        if (accounts.none { it.id == accountId }) return
        save(context, accounts.filterNot { it.id == accountId })
    }

    @Synchronized
    fun clear(context: Context) {
        val file = dataFile(context)
        if (file.exists() && !file.delete()) {
            throw GeneralSecurityException("Could not remove encrypted account storage.")
        }
    }

    private fun decodeAccounts(plaintext: ByteArray): List<VaultAccount> {
        val array = try {
            JSONArray(String(plaintext, StandardCharsets.UTF_8))
        } catch (error: Exception) {
            throw GeneralSecurityException("Encrypted account data is corrupted.", error)
        }
        if (array.length() > MAX_ACCOUNTS) {
            throw GeneralSecurityException("Encrypted account data exceeds the supported record count.")
        }

        val result = ArrayList<VaultAccount>(array.length())
        val ids = HashSet<String>(array.length())
        try {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index)
                    ?: throw GeneralSecurityException("An account record is invalid.")
                val account = VaultAccount(
                    id = item.getString("id"),
                    title = item.getString("title"),
                    username = item.optString("username", ""),
                    password = item.optString("password", ""),
                    website = item.optString("website", ""),
                    notes = item.optString("notes", ""),
                    category = item.optString("category", "Other"),
                    createdAt = item.optLong("createdAt", 0L),
                    updatedAt = item.optLong("updatedAt", 0L)
                )
                validate(account)
                if (!ids.add(account.id)) throw GeneralSecurityException("Duplicate account IDs were found.")
                result.add(account)
            }
            return result
        } catch (error: GeneralSecurityException) {
            throw error
        } catch (error: Exception) {
            throw GeneralSecurityException("An account record is corrupted.", error)
        }
    }

    private fun validate(account: VaultAccount) {
        require(account.id.isNotBlank() && account.id.length <= 64) { "Invalid account ID." }
        require(account.title.isNotBlank() && account.title.length <= 200) { "Account title is required (maximum 200 characters)." }
        require(account.username.length <= MAX_FIELD_LENGTH) { "Username is too long." }
        require(account.password.length <= MAX_FIELD_LENGTH) { "Password is too long." }
        require(account.website.length <= 2_048) { "Website address is too long." }
        require(account.notes.length <= MAX_FIELD_LENGTH) { "Notes are too long." }
        require(account.category.isNotBlank() && account.category.length <= 100) { "Invalid category." }
        require(account.createdAt >= 0L && account.updatedAt >= 0L) { "Invalid account timestamp." }
    }

    private fun atomicWrite(context: Context, bytes: ByteArray) {
        val target = dataFile(context)
        val directory = target.parentFile ?: throw GeneralSecurityException("Account storage directory is unavailable.")
        if (!directory.exists() && !directory.mkdirs()) {
            throw GeneralSecurityException("Could not create account storage directory.")
        }
        val temporary = File(directory, "$FILE_NAME.tmp")
        try {
            FileOutputStream(temporary, false).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            try {
                Files.move(
                    temporary.toPath(),
                    target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (error: Exception) {
            temporary.delete()
            if (error is GeneralSecurityException) throw error
            throw GeneralSecurityException("Could not safely save encrypted account data.", error)
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun dataFile(context: Context): File =
        File(context.applicationContext.noBackupFilesDir, FILE_NAME)

    private fun associatedData(): ByteArray =
        "VEYlora|encrypted-account-store|v1|AES-256-GCM".toByteArray(StandardCharsets.UTF_8)
}
