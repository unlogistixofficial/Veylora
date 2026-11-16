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
import java.util.Base64
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
data class AccountCustomField(
    val id: String = UUID.randomUUID().toString(),
    val label: String,
    val value: String
)

data class VaultAttachment(
    val id: String = UUID.randomUUID().toString(),
    val displayName: String,
    val mimeType: String,
    val sizeBytes: Long
)

data class VaultAccount(
    val id: String = UUID.randomUUID().toString(),
    val title: String,
    val username: String = "",
    val password: String = "",
    val website: String = "",
    val notes: String = "",
    val category: String = "Other",
    val customFields: List<AccountCustomField> = emptyList(),
    val attachments: List<VaultAttachment> = emptyList(),
    val isFavorite: Boolean = false,
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
    private const val MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
    private const val ATTACHMENT_DIR = "veylora_screenshots"
    private val ATTACHMENT_MAGIC = byteArrayOf(0x56, 0x45, 0x59, 0x53, 0x43, 0x52, 0x31)
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
                    .put("customFields", JSONArray().apply {
                        account.customFields.forEach { field ->
                            put(JSONObject().put("id", field.id).put("label", field.label).put("value", field.value))
                        }
                    })
                    .put("isFavorite", account.isFavorite)
                    .put("attachments", JSONArray().apply {
                        account.attachments.forEach { attachment ->
                            put(JSONObject().put("id", attachment.id)
                                .put("displayName", attachment.displayName)
                                .put("mimeType", attachment.mimeType)
                                .put("sizeBytes", attachment.sizeBytes))
                        }
                    })
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
        val account = accounts.firstOrNull { it.id == accountId } ?: return
        save(context, accounts.filterNot { it.id == accountId })
        account.attachments.forEach { attachment ->
            val file = attachmentFile(context, attachment.id)
            if (file.exists() && !file.delete()) {
                throw GeneralSecurityException("Account was deleted, but an encrypted screenshot file could not be removed.")
            }
        }
    }

    @Synchronized
    fun addScreenshot(context: Context, accountId: String, uri: android.net.Uri, displayName: String): VaultAttachment {
        val accounts = load(context).toMutableList()
        val index = accounts.indexOfFirst { it.id == accountId }
        if (index < 0) throw GeneralSecurityException("The account no longer exists.")
        val account = accounts[index]
        if (account.attachments.size >= 20) throw GeneralSecurityException("An account can have at most 20 screenshots.")

        val resolver = context.applicationContext.contentResolver
        val mimeType = resolver.getType(uri)?.lowercase()
        if (mimeType !in setOf("image/jpeg", "image/png", "image/webp")) {
            throw GeneralSecurityException("Choose a JPEG, PNG, or WebP screenshot.")
        }
        val input = resolver.openInputStream(uri)
            ?: throw GeneralSecurityException("Could not read the selected screenshot.")
        val plain = input.use { stream ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                total += count
                if (total > MAX_ATTACHMENT_BYTES) {
                    buffer.fill(0)
                    throw GeneralSecurityException("Screenshots must be 8 MB or smaller.")
                }
                output.write(buffer, 0, count)
            }
            buffer.fill(0)
            output.toByteArray()
        }
        if (plain.isEmpty()) throw GeneralSecurityException("The selected screenshot is empty.")

        val safeName = displayName
            .substringAfterLast('/')
            .filter { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' || it == ' ' }
            .take(180)
            .ifBlank { "Screenshot" }
        val attachment = VaultAttachment(
            displayName = safeName,
            mimeType = mimeType!!,
            sizeBytes = plain.size.toLong()
        )
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        var key: ByteArray? = null
        var encrypted: ByteArray? = null
        try {
            key = VaultSession.keyCopy()
            if (key.size != KEY_BYTES) throw GeneralSecurityException("Vault key has an invalid length.")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(attachmentAad(accountId, attachment.id))
            encrypted = cipher.doFinal(plain)
            val envelope = ByteBuffer.allocate(ATTACHMENT_MAGIC.size + NONCE_BYTES + encrypted.size)
                .put(ATTACHMENT_MAGIC).put(nonce).put(encrypted).array()
            try {
                atomicWriteAttachment(context, attachment.id, envelope)
            } finally {
                envelope.fill(0)
            }
            accounts[index] = account.copy(
                attachments = account.attachments + attachment,
                updatedAt = System.currentTimeMillis()
            )
            try {
                save(context, accounts)
            } catch (error: Exception) {
                attachmentFile(context, attachment.id).delete()
                throw error
            }
            return attachment
        } finally {
            plain.fill(0)
            nonce.fill(0)
            key?.fill(0)
            encrypted?.fill(0)
        }
    }

    @Synchronized
    fun removeScreenshot(context: Context, accountId: String, attachmentId: String) {
        val accounts = load(context).toMutableList()
        val index = accounts.indexOfFirst { it.id == accountId }
        if (index < 0) return
        val account = accounts[index]
        if (account.attachments.none { it.id == attachmentId }) return
        accounts[index] = account.copy(
            attachments = account.attachments.filterNot { it.id == attachmentId },
            updatedAt = System.currentTimeMillis()
        )
        save(context, accounts)
        val file = attachmentFile(context, attachmentId)
        if (file.exists() && !file.delete()) {
            throw GeneralSecurityException("Screenshot was detached, but its encrypted file could not be removed.")
        }
    }

    @Synchronized
    fun readScreenshot(context: Context, accountId: String, attachmentId: String): ByteArray {
        val account = load(context).firstOrNull { it.id == accountId }
            ?: throw GeneralSecurityException("Account not found.")
        val attachment = account.attachments.firstOrNull { it.id == attachmentId }
            ?: throw GeneralSecurityException("Screenshot not found.")
        val file = attachmentFile(context, attachmentId)
        if (!file.isFile || file.length() !in (ATTACHMENT_MAGIC.size + NONCE_BYTES + 16).toLong()..(MAX_ATTACHMENT_BYTES + ATTACHMENT_MAGIC.size + NONCE_BYTES + 16).toLong()) {
            throw GeneralSecurityException("Encrypted screenshot file is missing or invalid.")
        }
        val envelope = FileInputStream(file).use { it.readBytes() }
        var key: ByteArray? = null
        try {
            val headerSize = ATTACHMENT_MAGIC.size + NONCE_BYTES
            if (envelope.size < headerSize + 16 ||
                !envelope.copyOfRange(0, ATTACHMENT_MAGIC.size).contentEquals(ATTACHMENT_MAGIC)) {
                throw GeneralSecurityException("Encrypted screenshot format is invalid.")
            }
            val nonce = envelope.copyOfRange(ATTACHMENT_MAGIC.size, headerSize)
            val ciphertext = envelope.copyOfRange(headerSize, envelope.size)
            try {
                key = VaultSession.keyCopy()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
                cipher.updateAAD(attachmentAad(accountId, attachmentId))
                val plain = cipher.doFinal(ciphertext)
                if (plain.size.toLong() != attachment.sizeBytes) {
                    plain.fill(0)
                    throw GeneralSecurityException("Screenshot size does not match its encrypted metadata.")
                }
                return plain
            } finally {
                nonce.fill(0)
                ciphertext.fill(0)
            }
        } finally {
            key?.fill(0)
            envelope.fill(0)
        }
    }


    /**
     * Creates a portable plaintext snapshot. Callers must immediately protect the
     * returned bytes with VaultBackupCrypto and clear them after use.
     */
    @Synchronized
    fun exportBackupSnapshot(context: Context): ByteArray {
        val accounts = load(context)
        val accountArray = JSONArray()
        val screenshotArray = JSONArray()
        accounts.forEach { account ->
            accountArray.put(
                JSONObject()
                    .put("id", account.id)
                    .put("title", account.title)
                    .put("username", account.username)
                    .put("password", account.password)
                    .put("website", account.website)
                    .put("notes", account.notes)
                    .put("category", account.category)
                    .put("customFields", JSONArray().apply {
                        account.customFields.forEach { field ->
                            put(JSONObject().put("id", field.id).put("label", field.label).put("value", field.value))
                        }
                    })
                    .put("isFavorite", account.isFavorite)
                    .put("attachments", JSONArray().apply {
                        account.attachments.forEach { attachment ->
                            put(JSONObject().put("id", attachment.id)
                                .put("displayName", attachment.displayName)
                                .put("mimeType", attachment.mimeType)
                                .put("sizeBytes", attachment.sizeBytes))
                        }
                    })
                    .put("createdAt", account.createdAt)
                    .put("updatedAt", account.updatedAt)
            )
            account.attachments.forEach { attachment ->
                val imageBytes = readScreenshot(context, account.id, attachment.id)
                try {
                    screenshotArray.put(
                        JSONObject()
                            .put("accountId", account.id)
                            .put("attachmentId", attachment.id)
                            .put("data", Base64.getEncoder().encodeToString(imageBytes))
                    )
                } finally {
                    imageBytes.fill(0)
                }
            }
        }
        val snapshot = JSONObject()
            .put("format", "VEYloraBackup")
            .put("version", 1)
            .put("accounts", accountArray)
            .put("screenshots", screenshotArray)
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
        if (snapshot.isEmpty() || snapshot.size > 100 * 1024 * 1024) {
            snapshot.fill(0)
            throw GeneralSecurityException("Backup exceeds the supported 100 MB size.")
        }
        return snapshot
    }

    /**
     * Replaces the current vault only after the complete snapshot and every
     * screenshot have been validated and re-encrypted with this device's vault key.
     */
    @Synchronized
    fun restoreBackupSnapshot(context: Context, payload: ByteArray) {
        if (payload.isEmpty() || payload.size > 100 * 1024 * 1024) {
            throw GeneralSecurityException("Backup payload size is invalid.")
        }
        val root = try {
            JSONObject(String(payload, StandardCharsets.UTF_8))
        } catch (error: Exception) {
            throw GeneralSecurityException("Backup contents are invalid.", error)
        }
        if (root.optString("format") != "VEYloraBackup" || root.optInt("version", -1) != 1) {
            throw GeneralSecurityException("This backup format is not supported.")
        }
        val importedAccounts = decodeAccounts(
            root.optJSONArray("accounts")
                ?: throw GeneralSecurityException("Backup account data is missing.")
        )
        val oldAccounts = load(context)
        val screenshotRecords = root.optJSONArray("screenshots")
            ?: throw GeneralSecurityException("Backup screenshot data is missing.")
        val expectedScreenshots = importedAccounts.sumOf { it.attachments.size }
        if (screenshotRecords.length() != expectedScreenshots) {
            throw GeneralSecurityException("Backup screenshot data is incomplete.")
        }

        val attachmentData = HashMap<String, ByteArray>(expectedScreenshots)
        val knownAttachments = HashMap<String, Pair<String, VaultAttachment>>()
        importedAccounts.forEach { account ->
            account.attachments.forEach { attachment ->
                knownAttachments["${account.id}|${attachment.id}"] = account.id to attachment
            }
        }
        try {
            for (index in 0 until screenshotRecords.length()) {
                val record = screenshotRecords.optJSONObject(index)
                    ?: throw GeneralSecurityException("A backup screenshot record is invalid.")
                val accountId = record.optString("accountId")
                val attachmentId = record.optString("attachmentId")
                val key = "$accountId|$attachmentId"
                val known = knownAttachments[key]
                    ?: throw GeneralSecurityException("Backup contains an unlinked screenshot.")
                if (attachmentData.containsKey(key)) {
                    throw GeneralSecurityException("Backup contains duplicate screenshots.")
                }
                val encoded = record.optString("data")
                val bytes = try {
                    Base64.getDecoder().decode(encoded)
                } catch (error: Exception) {
                    throw GeneralSecurityException("A backup screenshot is corrupted.", error)
                }
                if (bytes.size.toLong() != known.second.sizeBytes ||
                    bytes.isEmpty() || bytes.size > MAX_ATTACHMENT_BYTES
                ) {
                    bytes.fill(0)
                    throw GeneralSecurityException("A backup screenshot does not match its metadata.")
                }
                attachmentData[key] = bytes
            }

            val remappedAccounts = ArrayList<VaultAccount>(importedAccounts.size)
            val pendingWrites = ArrayList<Triple<String, VaultAttachment, ByteArray>>(expectedScreenshots)
            importedAccounts.forEach { account ->
                val remappedAttachments = account.attachments.map { attachment ->
                    val bytes = attachmentData["${account.id}|${attachment.id}"]
                        ?: throw GeneralSecurityException("A backup screenshot is missing.")
                    val newAttachment = attachment.copy(id = UUID.randomUUID().toString())
                    pendingWrites.add(Triple(account.id, newAttachment, bytes))
                    newAttachment
                }
                val remapped = account.copy(attachments = remappedAttachments)
                validate(remapped)
                remappedAccounts.add(remapped)
            }

            val writtenFiles = ArrayList<File>(pendingWrites.size)
            try {
                pendingWrites.forEach { (accountId, attachment, bytes) ->
                    writeScreenshotBytes(context, accountId, attachment, bytes)
                    writtenFiles.add(attachmentFile(context, attachment.id))
                }
                save(context, remappedAccounts)
            } catch (error: Exception) {
                writtenFiles.forEach { it.delete() }
                throw error
            }

            oldAccounts.flatMap { it.attachments }.forEach { oldAttachment ->
                attachmentFile(context, oldAttachment.id).delete()
            }
        } finally {
            attachmentData.values.forEach { it.fill(0) }
        }
    }

    private fun writeScreenshotBytes(
        context: Context,
        accountId: String,
        attachment: VaultAttachment,
        plaintext: ByteArray
    ) {
        if (plaintext.isEmpty() || plaintext.size.toLong() != attachment.sizeBytes ||
            plaintext.size > MAX_ATTACHMENT_BYTES
        ) {
            throw GeneralSecurityException("Screenshot data does not match its metadata.")
        }
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        var key: ByteArray? = null
        var ciphertext: ByteArray? = null
        try {
            key = VaultSession.keyCopy()
            if (key.size != KEY_BYTES) throw GeneralSecurityException("Vault key has an invalid length.")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(attachmentAad(accountId, attachment.id))
            ciphertext = cipher.doFinal(plaintext)
            val envelope = ByteBuffer.allocate(ATTACHMENT_MAGIC.size + NONCE_BYTES + ciphertext.size)
                .put(ATTACHMENT_MAGIC).put(nonce).put(ciphertext).array()
            try {
                atomicWriteAttachment(context, attachment.id, envelope)
            } finally {
                envelope.fill(0)
            }
        } finally {
            nonce.fill(0)
            key?.fill(0)
            ciphertext?.fill(0)
        }
    }

    @Synchronized
    fun clear(context: Context) {
        val file = dataFile(context)
        if (file.exists() && !file.delete()) {
            throw GeneralSecurityException("Could not remove encrypted account storage.")
        }
        val directory = File(context.applicationContext.noBackupFilesDir, ATTACHMENT_DIR)
        if (directory.exists() && !directory.deleteRecursively()) {
            throw GeneralSecurityException("Could not remove encrypted screenshot storage.")
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
                    customFields = decodeCustomFields(item.optJSONArray("customFields")),
                    attachments = decodeAttachments(item.optJSONArray("attachments")),
                    isFavorite = item.optBoolean("isFavorite", false),
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

    private fun decodeCustomFields(array: JSONArray?): List<AccountCustomField> {
        if (array == null) return emptyList()
        if (array.length() > 30) throw GeneralSecurityException("Too many custom fields in an account.")
        val fields = ArrayList<AccountCustomField>(array.length())
        val ids = HashSet<String>(array.length())
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index)
                ?: throw GeneralSecurityException("A custom field is invalid.")
            val field = try {
                AccountCustomField(
                    id = item.getString("id"),
                    label = item.getString("label"),
                    value = item.getString("value")
                )
            } catch (error: Exception) {
                throw GeneralSecurityException("A custom field is corrupted.", error)
            }
            if (field.id.isBlank() || field.id.length > 64 || !ids.add(field.id) ||
                field.label.isBlank() || field.label.length > 100 || field.value.length > MAX_FIELD_LENGTH
            ) {
                throw GeneralSecurityException("A custom field contains invalid data.")
            }
            fields.add(field)
        }
        return fields
    }

    private fun decodeAttachments(array: JSONArray?): List<VaultAttachment> {
        if (array == null) return emptyList()
        if (array.length() > 20) throw GeneralSecurityException("Too many attachments in an account.")
        val result = ArrayList<VaultAttachment>(array.length())
        val ids = HashSet<String>(array.length())
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index)
                ?: throw GeneralSecurityException("An attachment record is invalid.")
            val attachment = try {
                VaultAttachment(
                    id = item.getString("id"),
                    displayName = item.getString("displayName"),
                    mimeType = item.getString("mimeType"),
                    sizeBytes = item.getLong("sizeBytes")
                )
            } catch (error: Exception) {
                throw GeneralSecurityException("An attachment record is corrupted.", error)
            }
            if (attachment.id.isBlank() || attachment.id.length > 64 || !ids.add(attachment.id) ||
                attachment.displayName.isBlank() || attachment.displayName.length > 180 ||
                attachment.mimeType != "image/jpeg" && attachment.mimeType != "image/png" &&
                attachment.mimeType != "image/webp" ||
                attachment.sizeBytes !in 1..(8L * 1024 * 1024)
            ) throw GeneralSecurityException("An attachment record contains invalid data.")
            result.add(attachment)
        }
        return result
    }

    private fun validate(account: VaultAccount) {
        require(account.id.isNotBlank() && account.id.length <= 64) { "Invalid account ID." }
        require(account.title.isNotBlank() && account.title.length <= 200) { "Account title is required (maximum 200 characters)." }
        require(account.username.length <= MAX_FIELD_LENGTH) { "Username is too long." }
        require(account.password.length <= MAX_FIELD_LENGTH) { "Password is too long." }
        require(account.website.length <= 2_048) { "Website address is too long." }
        require(account.notes.length <= MAX_FIELD_LENGTH) { "Notes are too long." }
        require(account.category.isNotBlank() && account.category.length <= 100) { "Invalid category." }
        require(account.customFields.size <= 30) { "An account can have at most 30 custom fields." }
        require(account.attachments.size <= 20) { "An account can have at most 20 screenshot attachments." }
        val attachmentIds = HashSet<String>(account.attachments.size)
        account.attachments.forEach { attachment ->
            require(attachment.id.isNotBlank() && attachment.id.length <= 64 && attachmentIds.add(attachment.id)) { "Invalid attachment ID." }
            require(attachment.displayName.isNotBlank() && attachment.displayName.length <= 180) { "Invalid attachment name." }
            require(attachment.mimeType in setOf("image/jpeg", "image/png", "image/webp")) { "Unsupported screenshot format." }
            require(attachment.sizeBytes in 1..(8L * 1024 * 1024)) { "Screenshot size is invalid." }
        }
        val fieldIds = HashSet<String>(account.customFields.size)
        account.customFields.forEach { field ->
            require(field.id.isNotBlank() && field.id.length <= 64 && fieldIds.add(field.id)) { "Invalid custom field ID." }
            require(field.label.isNotBlank() && field.label.length <= 100) { "Custom field names must contain 1–100 characters." }
            require(field.value.length <= MAX_FIELD_LENGTH) { "Custom field value is too long." }
        }
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

    private fun attachmentAad(accountId: String, attachmentId: String): ByteArray =
        "VEYlora|screenshot|v1|$accountId|$attachmentId".toByteArray(StandardCharsets.UTF_8)

    private fun attachmentFile(context: Context, attachmentId: String): File {
        require(attachmentId.matches(Regex("[A-Za-z0-9-]{1,64}"))) { "Invalid attachment ID." }
        return File(File(context.applicationContext.noBackupFilesDir, ATTACHMENT_DIR), "$attachmentId.bin")
    }

    private fun atomicWriteAttachment(context: Context, attachmentId: String, bytes: ByteArray) {
        val target = attachmentFile(context, attachmentId)
        val directory = target.parentFile ?: throw GeneralSecurityException("Screenshot storage directory is unavailable.")
        if (!directory.exists() && !directory.mkdirs()) throw GeneralSecurityException("Could not create screenshot storage.")
        val temporary = File(directory, "$attachmentId.tmp")
        try {
            FileOutputStream(temporary, false).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            try {
                Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (error: Exception) {
            temporary.delete()
            throw GeneralSecurityException("Could not safely save encrypted screenshot.", error)
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun dataFile(context: Context): File =
        File(context.applicationContext.noBackupFilesDir, FILE_NAME)

    private fun associatedData(): ByteArray =
        "VEYlora|encrypted-account-store|v1|AES-256-GCM".toByteArray(StandardCharsets.UTF_8)
}
