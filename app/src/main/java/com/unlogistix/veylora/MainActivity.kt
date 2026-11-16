package com.unlogistix.veylora

import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager
import androidx.core.content.ContextCompat
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import android.net.Uri
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.unlogistix.veylora.security.InvalidMasterPasswordException
import com.unlogistix.veylora.security.AccountVaultStore
import com.unlogistix.veylora.security.VaultAccount
import com.unlogistix.veylora.security.AccountCustomField
import com.unlogistix.veylora.security.VaultAttachment
import com.unlogistix.veylora.security.BiometricVaultUnlock
import com.unlogistix.veylora.security.PinVaultUnlock
import com.unlogistix.veylora.security.PinUnlockResult
import com.unlogistix.veylora.security.VaultCrypto
import com.unlogistix.veylora.security.VaultSession
import javax.crypto.Cipher
import androidx.compose.foundation.background
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.unlogistix.veylora.ui.theme.VeyloraBlack
import com.unlogistix.veylora.ui.theme.VeyloraGold
import com.unlogistix.veylora.ui.theme.VeyloraMuted
import com.unlogistix.veylora.ui.theme.VeyloraSurface
import com.unlogistix.veylora.ui.theme.VeyloraText
import com.unlogistix.veylora.ui.theme.VeyloraTheme

private enum class VeyloraTab(val label: String, val symbol: String) {
    HOME("Home", "⌂"),
    FAVORITES("Favorites", "☆"),
    SEARCH("Search", "⌕"),
    SETTINGS("Settings", "⚙")
}

class MainActivity : FragmentActivity() {
    private var sessionVersion by mutableIntStateOf(0)
    private var externalPickerActive = false

    fun beginExternalPicker() {
        externalPickerActive = true
    }

    fun finishExternalPicker() {
        externalPickerActive = false
    }


    fun enableBiometricUnlock(onResult: (Boolean, String?) -> Unit) {
        val capability = BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (capability != BiometricManager.BIOMETRIC_SUCCESS) {
            onResult(false, "Strong biometrics are not available or enrolled on this device.")
            return
        }
        try {
            val cipher = BiometricVaultUnlock.prepareEnrollmentCipher()
            val prompt = biometricPrompt(
                onSuccess = { authenticated ->
                    try {
                        BiometricVaultUnlock.finishEnrollment(
                            this,
                            authenticated.cryptoObject?.cipher
                                ?: throw IllegalStateException("Biometric cipher is unavailable.")
                        )
                        onResult(true, null)
                    } catch (error: Exception) {
                        BiometricVaultUnlock.disable(this)
                        onResult(false, "Could not enable biometric unlock. Use your master password.")
                    }
                },
                onError = { message -> BiometricVaultUnlock.disable(this); onResult(false, message) }
            )
            prompt.authenticate(biometricPromptInfo("Enable biometric unlock"), BiometricPrompt.CryptoObject(cipher))
        } catch (error: Exception) {
            onResult(false, "Biometric unlock is unavailable on this device.")
        }
    }

    fun unlockWithBiometric(onResult: (Boolean, String?) -> Unit) {
        try {
            val (cipher, encryptedKey) = BiometricVaultUnlock.prepareUnlock(this)
            val prompt = biometricPrompt(
                onSuccess = { authenticated ->
                    try {
                        BiometricVaultUnlock.finishUnlock(
                            authenticated.cryptoObject?.cipher
                                ?: throw IllegalStateException("Biometric cipher is unavailable."),
                            encryptedKey
                        )
                        onResult(true, null)
                    } catch (error: Exception) {
                        onResult(false, "Biometric unlock failed. Use your master password.")
                    }
                },
                onError = { message -> encryptedKey.fill(0); onResult(false, message) }
            )
            prompt.authenticate(biometricPromptInfo("Unlock Veylora"), BiometricPrompt.CryptoObject(cipher))
        } catch (error: Exception) {
            onResult(false, "Biometric unlock is unavailable. Use your master password.")
        }
    }

    private fun biometricPrompt(
        onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
        onError: (String) -> Unit
    ): BiometricPrompt {
        return BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess(result)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }
            }
        )
    }

    private fun biometricPromptInfo(title: String): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle("Authenticate with your device biometrics")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()

    override fun onStart() {
        super.onStart()
        externalPickerActive = false
    }

    override fun onStop() {
        if (!externalPickerActive) {
            VaultSession.lock()
            sessionVersion++
        }
        super.onStop()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContent {
            VeyloraTheme {
                VeyloraApp(sessionVersion)
            }
        }
    }
}

@Composable
private fun VeyloraApp(sessionVersion: Int) {
    val context = LocalContext.current
    val activity = context as? MainActivity
    val initialized = remember(sessionVersion) { VaultCrypto.isInitialized(context) }
    var unlocked by remember(sessionVersion) { mutableStateOf(VaultSession.isUnlocked()) }

    if (unlocked) {
        VeyloraDashboard(activity)
    } else {
        VaultGateScreen(
            initialized = initialized,
            biometricAvailable = BiometricVaultUnlock.isEnabled(context),
            pinAvailable = PinVaultUnlock.isEnabled(context),
            pinLockedOut = PinVaultUnlock.wasLockedOut(context),
            activity = activity,
            onUnlocked = { unlocked = true }
        )
    }
}

@Composable
private fun VeyloraDashboard(activity: MainActivity?) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var selectedTab by remember { mutableStateOf(VeyloraTab.HOME) }
    var searchQuery by remember { mutableStateOf("") }
    var showEditor by remember { mutableStateOf(false) }
    var editingAccount by remember { mutableStateOf<VaultAccount?>(null) }
    var pendingDelete by remember { mutableStateOf<VaultAccount?>(null) }
    var storageError by remember { mutableStateOf<String?>(null) }
    var accountsLoaded by remember { mutableStateOf(false) }
    val accounts = remember { mutableStateListOf<VaultAccount>() }

    LaunchedEffect(context) {
        try {
            val stored = withContext(Dispatchers.IO) { AccountVaultStore.load(context) }
            accounts.clear()
            accounts.addAll(stored)
            storageError = null
        } catch (_: Exception) {
            storageError = "Could not read the encrypted vault. Your stored data has not been changed."
        } finally {
            accountsLoaded = true
        }
    }

    fun toggleFavorite(account: VaultAccount) {
        scope.launch {
            try {
                val updated = account.copy(isFavorite = !account.isFavorite)
                val stored = withContext(Dispatchers.IO) {
                    AccountVaultStore.upsert(context, updated)
                    AccountVaultStore.load(context)
                }
                accounts.clear()
                accounts.addAll(stored)
                storageError = null
            } catch (_: Exception) {
                storageError = "Could not update favorite status."
            }
        }
    }

    fun refreshAccounts() {
        scope.launch {
            try {
                val stored = withContext(Dispatchers.IO) { AccountVaultStore.load(context) }
                accounts.clear()
                accounts.addAll(stored)
                storageError = null
            } catch (_: Exception) {
                storageError = "Could not refresh encrypted account storage."
            }
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = VeyloraBlack) {
        androidx.compose.material3.Scaffold(
            containerColor = VeyloraBlack,
            bottomBar = {
                NavigationBar(containerColor = Color(0xFF111113), contentColor = VeyloraText) {
                    VeyloraTab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = selectedTab == tab,
                            onClick = { selectedTab = tab },
                            icon = {
                                Text(tab.symbol, fontSize = 21.sp,
                                    color = if (selectedTab == tab) VeyloraGold else VeyloraMuted)
                            },
                            label = { Text(tab.label, fontSize = 11.sp) }
                        )
                    }
                }
            }
        ) { innerPadding ->
            Box(Modifier.fillMaxSize().padding(innerPadding)) {
                when (selectedTab) {
                    VeyloraTab.HOME -> HomeScreen(
                        accounts = accounts,
                        accountsLoaded = accountsLoaded,
                        onAddClick = { editingAccount = null; showEditor = true },
                        onEdit = { editingAccount = it; showEditor = true },
                        onToggleFavorite = { account -> toggleFavorite(account) },
                        onDelete = { account -> pendingDelete = account }
                    )
                    VeyloraTab.FAVORITES -> FavoritesScreen(
                        accounts = accounts.filter { it.isFavorite },
                        onEdit = { editingAccount = it; showEditor = true },
                        onToggleFavorite = { account -> toggleFavorite(account) }
                    )
                    VeyloraTab.SEARCH -> SearchScreen(
                        query = searchQuery,
                        onQueryChange = { searchQuery = it },
                        accounts = accounts,
                        onEdit = { editingAccount = it; showEditor = true }
                    )
                    VeyloraTab.SETTINGS -> SettingsScreen(
                        biometricEnabled = activity?.let { BiometricVaultUnlock.isEnabled(it) } == true,
                        onEnableBiometric = { callback -> activity?.enableBiometricUnlock(callback) },
                        onDisableBiometric = { activity?.let { BiometricVaultUnlock.disable(it) } },
                        pinEnabled = activity?.let { PinVaultUnlock.isEnabled(it) } == true,
                        onEnablePin = { value ->
                            try {
                                activity?.let { PinVaultUnlock.enable(it, value.toCharArray()); true } ?: false
                            } catch (_: Exception) { false }
                        },
                        onDisablePin = { activity?.let { PinVaultUnlock.disable(it) } }
                    )
                }
            }
        }
    }

    if (storageError != null) {
        AlertDialog(
            onDismissRequest = { storageError = null },
            containerColor = VeyloraSurface,
            title = { Text("Vault storage notice", color = VeyloraText) },
            text = { Text(storageError!!, color = VeyloraMuted) },
            confirmButton = {
                TextButton(onClick = { storageError = null }) {
                    Text("OK", color = VeyloraGold)
                }
            }
        )
    }

    if (pendingDelete != null) {
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            containerColor = VeyloraSurface,
            title = { Text("Delete account?", color = VeyloraText) },
            text = {
                Text("This permanently removes “${pendingDelete!!.title}” from this device's encrypted vault.",
                    color = VeyloraMuted)
            },
            confirmButton = {
                TextButton(onClick = {
                    val accountToDelete = pendingDelete
                    pendingDelete = null
                    if (accountToDelete != null) {
                        scope.launch {
                            try {
                                val stored = withContext(Dispatchers.IO) {
                                    AccountVaultStore.delete(context, accountToDelete.id)
                                    AccountVaultStore.load(context)
                                }
                                accounts.clear()
                                accounts.addAll(stored)
                                storageError = null
                            } catch (_: Exception) {
                                storageError = "Could not delete this account. The encrypted vault was left unchanged."
                            }
                        }
                    }
                }) { Text("Delete", color = Color(0xFFFF8A80)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text("Cancel", color = VeyloraMuted)
                }
            }
        )
    }

    if (showEditor) {
        AccountEditorDialog(
            account = editingAccount,
            onDismiss = { showEditor = false; editingAccount = null },
            onSave = { account ->
                scope.launch {
                    try {
                        val stored = withContext(Dispatchers.IO) {
                            AccountVaultStore.upsert(context, account)
                            AccountVaultStore.load(context)
                        }
                        accounts.clear()
                        accounts.addAll(stored)
                        storageError = null
                        showEditor = false
                        editingAccount = null
                    } catch (error: IllegalArgumentException) {
                        storageError = error.message ?: "Please check the account details."
                    } catch (_: Exception) {
                        storageError = "Could not save the account securely. Your existing vault data was preserved."
                    }
                }
            }
        )
    }
}

@Composable
private fun VaultGateScreen(
    initialized: Boolean,
    biometricAvailable: Boolean,
    pinAvailable: Boolean,
    pinLockedOut: Boolean,
    activity: MainActivity?,
    onUnlocked: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var pinEnabled by remember { mutableStateOf(pinAvailable) }
    var confirmation by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .background(VeyloraBlack).padding(horizontal = 26.dp, vertical = 34.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier.size(62.dp).background(VeyloraSurface, CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Text("V", color = VeyloraGold, fontSize = 34.sp, fontWeight = FontWeight.Light)
        }
        Spacer(Modifier.height(18.dp))
        Text("VEY LORA".replace(" ", ""), color = VeyloraText, fontSize = 25.sp,
            letterSpacing = 4.sp, fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(8.dp))
        Text("YOUR DIGITAL LIFE, SECURED.", color = VeyloraMuted,
            fontSize = 10.sp, letterSpacing = 1.8.sp)
        Spacer(Modifier.height(42.dp))
        Text(
            if (initialized) "Welcome back" else "Create your master password",
            color = VeyloraText, fontSize = 23.sp, fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.height(9.dp))
        Text(
            if (initialized) "Unlock your private vault to continue."
            else "This password protects the encryption key for your future vault data.",
            color = VeyloraMuted, fontSize = 13.sp, lineHeight = 19.sp
        )
        Spacer(Modifier.height(24.dp))
        if (initialized && pinLockedOut) {
            Text("PIN unlock was disabled after five incorrect attempts. Use your master password.",
                color = VeyloraGold, fontSize = 12.sp, lineHeight = 17.sp)
            Spacer(Modifier.height(12.dp))
        }
        OutlinedTextField(
            value = password,
            onValueChange = { password = it; error = null },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Master password") },
            placeholder = { Text("Enter master password") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            shape = RoundedCornerShape(14.dp)
        )
        if (initialized && pinEnabled) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = pin,
                onValueChange = { value -> if (value.length <= 12 && value.all(Char::isDigit)) { pin = value; error = null } },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("App PIN") },
                placeholder = { Text("Enter your 6–12 digit PIN") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                shape = RoundedCornerShape(14.dp)
            )
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = {
                    if (pin.length !in 6..12) {
                        error = "Enter your 6–12 digit PIN."
                    } else if (!busy) {
                        busy = true
                        val enteredPin = pin.toCharArray()
                        pin = ""
                        scope.launch {
                            val result = withContext(Dispatchers.Default) {
                                try { PinVaultUnlock.unlock(context, enteredPin) }
                                catch (_: Exception) { PinUnlockResult.WRONG_PIN }
                                finally { enteredPin.fill('\u0000') }
                            }
                            busy = false
                            when (result) {
                                PinUnlockResult.SUCCESS -> onUnlocked()
                                PinUnlockResult.WRONG_PIN -> error = "Incorrect PIN. Try again or use your master password."
                                PinUnlockResult.LOCKED_OUT -> { pinEnabled = false; error = "Five incorrect attempts. Unlock with your master password." }
                            }
                        }
                    }
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = VeyloraSurface, contentColor = VeyloraGold)
            ) { Text(if (busy) "Checking PIN…" else "Unlock with PIN") }
        }
        if (!initialized) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = confirmation,
                onValueChange = { confirmation = it; error = null },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("Confirm master password") },
                placeholder = { Text("Re-enter master password") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                shape = RoundedCornerShape(14.dp)
            )
            Spacer(Modifier.height(10.dp))
            Text("Use at least 10 characters. If you lose this password, your vault cannot currently be recovered.",
                color = VeyloraMuted, fontSize = 11.sp, lineHeight = 16.sp)
        }
        if (error != null) {
            Spacer(Modifier.height(12.dp))
            Text(error!!, color = Color(0xFFFF8A80), fontSize = 12.sp)
        }
        Spacer(Modifier.height(22.dp))
        Button(
            onClick = {
                if (busy) return@Button
                if (password.isBlank()) {
                    error = "Enter your master password."
                } else if (!initialized && password.length < 10) {
                    error = "Choose a master password with at least 10 characters."
                } else if (!initialized && password != confirmation) {
                    error = "The passwords do not match."
                } else {
                    busy = true
                    error = null
                    val secret = password.toCharArray()
                    password = ""
                    confirmation = ""
                    scope.launch {
                        val result = withContext(Dispatchers.Default) {
                            try {
                                if (initialized) VaultCrypto.unlock(context, secret)
                                else VaultCrypto.create(context, secret)
                                null
                            } catch (badPassword: InvalidMasterPasswordException) {
                                "That master password is incorrect."
                            } catch (failure: Exception) {
                                "Vault setup could not be completed. Please try again."
                            } finally {
                                secret.fill('\u0000')
                            }
                        }
                        busy = false
                        if (result == null) onUnlocked() else error = result
                    }
                }
            },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = VeyloraGold,
                contentColor = VeyloraBlack
            )
        ) {
            Text(
                if (busy) "Please wait…" else if (initialized) "Unlock vault" else "Create secure vault",
                fontWeight = FontWeight.SemiBold
            )
        }
        if (initialized && biometricAvailable && activity != null) {
            Spacer(Modifier.height(12.dp))
            TextButton(
                onClick = {
                    activity.unlockWithBiometric { success, message ->
                        if (success) onUnlocked() else error = message
                    }
                }
            ) {
                Text("Unlock with biometrics", color = VeyloraGold)
            }
        }
        Spacer(Modifier.height(22.dp))
        Text("Your master password is never saved by Veylora.",
            color = VeyloraMuted, fontSize = 11.sp)
    }
}

@Composable
private fun HomeScreen(
    accounts: List<VaultAccount>,
    accountsLoaded: Boolean,
    onAddClick: () -> Unit,
    onEdit: (VaultAccount) -> Unit,
    onToggleFavorite: (VaultAccount) -> Unit,
    onDelete: (VaultAccount) -> Unit
) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal = 22.dp, vertical = 20.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("VEYLORA", color = VeyloraText, fontSize = 19.sp,
                    letterSpacing = 3.sp, fontWeight = FontWeight.SemiBold)
                Text("YOUR PRIVATE SPACE", color = VeyloraMuted, fontSize = 9.sp,
                    letterSpacing = 2.sp)
            }
            Box(Modifier.size(42.dp).background(VeyloraSurface, CircleShape),
                contentAlignment = Alignment.Center) {
                Text("V", color = VeyloraGold, fontSize = 22.sp, fontWeight = FontWeight.Light)
            }
        }

        Spacer(Modifier.height(30.dp))
        Text("Good to see you.", color = VeyloraMuted, fontSize = 14.sp)
        Text("Your digital life,\nbeautifully secured.", color = VeyloraText,
            fontSize = 27.sp, lineHeight = 34.sp, fontWeight = FontWeight.Medium)

        Spacer(Modifier.height(24.dp))
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(22.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF201D17))
        ) {
            Column(Modifier.padding(20.dp)) {
                Text("VAULT STATUS", color = VeyloraGold, fontSize = 11.sp,
                    letterSpacing = 1.8.sp, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(14.dp))
                Text("Encrypted account vault", color = VeyloraText, fontSize = 21.sp,
                    fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp))
                Text("Account details are encrypted on this device with your vault key.",
                    color = VeyloraMuted, fontSize = 13.sp, lineHeight = 19.sp)
                Spacer(Modifier.height(18.dp))
                Button(
                    onClick = onAddClick,
                    colors = ButtonDefaults.buttonColors(containerColor = VeyloraGold,
                        contentColor = VeyloraBlack),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("＋   Add account", fontWeight = FontWeight.SemiBold)
                }
            }
        }

        Spacer(Modifier.height(22.dp))
        Text("OVERVIEW", color = VeyloraMuted, fontSize = 11.sp,
            letterSpacing = 1.8.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OverviewCard(if (accountsLoaded) accounts.size.toString() else "—", "ACCOUNTS", Modifier.weight(1f))
            OverviewCard("—", "FAVORITES", Modifier.weight(1f))
        }

        Spacer(Modifier.height(26.dp))
        Text("YOUR ACCOUNTS", color = VeyloraMuted, fontSize = 11.sp,
            letterSpacing = 1.8.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(10.dp))
        if (!accountsLoaded) {
            Text("Unlocking encrypted records…", color = VeyloraMuted, fontSize = 13.sp)
        } else if (accounts.isEmpty()) {
            Text("Your vault is empty. Add your first account to get started.",
                color = VeyloraMuted, fontSize = 13.sp, lineHeight = 19.sp)
        } else {
            accounts.forEach { account ->
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp),
                    shape = RoundedCornerShape(15.dp),
                    colors = CardDefaults.cardColors(containerColor = VeyloraSurface)
                ) {
                    Column(Modifier.padding(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(account.title, color = VeyloraText, fontSize = 15.sp,
                                fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                            TextButton(onClick = { onToggleFavorite(account) }) {
                                Text(if (account.isFavorite) "★" else "☆",
                                    color = VeyloraGold, fontSize = 20.sp)
                            }
                        }
                        Spacer(Modifier.height(3.dp))
                        Text(
                            account.username.ifBlank { account.website.ifBlank { account.category } },
                            color = VeyloraMuted, fontSize = 12.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick = { onEdit(account) }) {
                                Text("Edit", color = VeyloraGold)
                            }
                            TextButton(onClick = { onDelete(account) }) {
                                Text("Delete", color = Color(0xFFFF8A80))
                            }
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(20.dp))
        Text("Account records are encrypted before they are written to app-private storage.",
            color = VeyloraMuted, fontSize = 11.sp, lineHeight = 16.sp)
    }
}

@Composable
private fun FavoritesScreen(
    accounts: List<VaultAccount>,
    onEdit: (VaultAccount) -> Unit,
    onToggleFavorite: (VaultAccount) -> Unit
) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(22.dp)) {
        Text("Favorites", color = VeyloraText, fontSize = 27.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text("Your starred accounts, kept inside your encrypted vault.", color = VeyloraMuted, fontSize = 13.sp)
        Spacer(Modifier.height(18.dp))
        if (accounts.isEmpty()) {
            Text("No favorites yet. Star an account on the Home screen to add it here.",
                color = VeyloraMuted, fontSize = 13.sp, lineHeight = 19.sp)
        } else {
            accounts.forEach { account ->
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = VeyloraSurface),
                    onClick = { onEdit(account) }
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(account.title, color = VeyloraText, fontWeight = FontWeight.SemiBold)
                            Text(account.username.ifBlank { account.website.ifBlank { account.category } },
                                color = VeyloraMuted, fontSize = 12.sp)
                        }
                        TextButton(onClick = { onToggleFavorite(account) }) {
                            Text("★", color = VeyloraGold, fontSize = 20.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun OverviewCard(value: String, label: String, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = VeyloraSurface)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(value, color = VeyloraText, fontSize = 25.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(label, color = VeyloraMuted, fontSize = 10.sp, letterSpacing = 1.2.sp)
        }
    }
}

@Composable
private fun CategoryRow(symbol: String, title: String, subtitle: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .background(VeyloraSurface, RoundedCornerShape(15.dp))
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier.size(40.dp).background(Color(0xFF28241D), RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text(symbol, color = VeyloraGold, fontSize = 19.sp)
        }
        Spacer(Modifier.size(12.dp))
        Column {
            Text(title, color = VeyloraText, fontSize = 14.sp, fontWeight = FontWeight.Medium)
            Spacer(Modifier.height(3.dp))
            Text(subtitle, color = VeyloraMuted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun EmptyCollectionScreen(title: String, message: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(26.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("☆", color = VeyloraGold, fontSize = 42.sp)
        Spacer(Modifier.height(14.dp))
        Text(title, color = VeyloraText, fontSize = 22.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text(message, color = VeyloraMuted, fontSize = 13.sp, lineHeight = 19.sp)
        Spacer(Modifier.height(12.dp))
        Text("Your vault is currently empty.", color = VeyloraMuted, fontSize = 12.sp)
    }
}

@Composable
private fun SearchScreen(
    query: String,
    onQueryChange: (String) -> Unit,
    accounts: List<VaultAccount>,
    onEdit: (VaultAccount) -> Unit
) {
    val filtered = accounts.filter { account ->
        query.isBlank() ||
            account.title.contains(query, ignoreCase = true) ||
            account.username.contains(query, ignoreCase = true) ||
            account.website.contains(query, ignoreCase = true) ||
            account.category.contains(query, ignoreCase = true)
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(22.dp)) {
        Text("Search", color = VeyloraText, fontSize = 27.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text("Find an account in your encrypted vault.", color = VeyloraMuted, fontSize = 13.sp)
        Spacer(Modifier.height(20.dp))
        OutlinedTextField(
            value = query,
            onValueChange = onQueryChange,
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            placeholder = { Text("Search accounts", color = VeyloraMuted) },
            leadingIcon = { Text("⌕", color = VeyloraGold, fontSize = 22.sp) },
            shape = RoundedCornerShape(14.dp)
        )
        Spacer(Modifier.height(18.dp))
        if (filtered.isEmpty()) {
            Text(if (query.isBlank()) "No accounts saved yet." else "No matching accounts found.",
                color = VeyloraMuted, fontSize = 13.sp)
        } else {
            filtered.forEach { account ->
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = VeyloraSurface),
                    onClick = { onEdit(account) }
                ) {
                    Column(Modifier.padding(14.dp)) {
                        Text(account.title, color = VeyloraText, fontWeight = FontWeight.Medium)
                        Text(account.username.ifBlank { account.website },
                            color = VeyloraMuted, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

private fun generateSecurePassword(length: Int): String {
    require(length in 12..64)
    val random = java.security.SecureRandom()
    val upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    val lower = "abcdefghijkmnopqrstuvwxyz"
    val digits = "23456789"
    val symbols = "!@#$%&*()-_=+[]{}?"
    val all = upper + lower + digits + symbols
    val result = ArrayList<Char>(length)
    result.add(upper[random.nextInt(upper.length)])
    result.add(lower[random.nextInt(lower.length)])
    result.add(digits[random.nextInt(digits.length)])
    result.add(symbols[random.nextInt(symbols.length)])
    repeat(length - result.size) { result.add(all[random.nextInt(all.length)]) }
    for (index in result.lastIndex downTo 1) {
        val swapIndex = random.nextInt(index + 1)
        val value = result[index]
        result[index] = result[swapIndex]
        result[swapIndex] = value
    }
    return result.joinToString("")
}

@Composable
private fun AccountEditorDialog(
    account: VaultAccount?,
    onDismiss: () -> Unit,
    onSave: (VaultAccount) -> Unit
) {
    var title by remember(account?.id) { mutableStateOf(account?.title.orEmpty()) }
    var username by remember(account?.id) { mutableStateOf(account?.username.orEmpty()) }
    var password by remember(account?.id) { mutableStateOf(account?.password.orEmpty()) }
    var website by remember(account?.id) { mutableStateOf(account?.website.orEmpty()) }
    var notes by remember(account?.id) { mutableStateOf(account?.notes.orEmpty()) }
    var category by remember(account?.id) { mutableStateOf(account?.category ?: "Other") }
    var categoryExpanded by remember { mutableStateOf(false) }
    val customFields = remember(account?.id) {
        mutableStateListOf<AccountCustomField>().apply { addAll(account?.customFields.orEmpty()) }
    }
    val attachments = remember(account?.id) {
        mutableStateListOf<VaultAttachment>().apply { addAll(account?.attachments.orEmpty()) }
    }
    val context = LocalContext.current
    val activity = context as? MainActivity
    val scope = rememberCoroutineScope()
    var error by remember { mutableStateOf<String?>(null) }
    var previewBitmap by remember { mutableStateOf<Bitmap?>(null) }
    var previewName by remember { mutableStateOf("") }
    val screenshotPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        activity?.finishExternalPicker()
        val existingAccount = account
        if (uri != null && existingAccount != null) {
            scope.launch {
                try {
                    val saved = withContext(Dispatchers.IO) {
                        AccountVaultStore.addScreenshot(
                            context,
                            existingAccount.id,
                            uri,
                            uri.lastPathSegment ?: "Screenshot"
                        )
                    }
                    attachments.add(saved)
                    error = null
                } catch (failure: Exception) {
                    error = failure.message ?: "Could not securely attach this screenshot."
                }
            }
        }
    }
    val categories = listOf("Social", "Email", "Finance", "Gaming", "Work", "Shopping", "Entertainment", "Other")

    if (previewBitmap != null) {
        AlertDialog(
            onDismissRequest = {
                previewBitmap?.recycle()
                previewBitmap = null
            },
            containerColor = VeyloraSurface,
            title = { Text(previewName, color = VeyloraText) },
            text = {
                Image(
                    bitmap = previewBitmap!!.asImageBitmap(),
                    contentDescription = previewName,
                    modifier = Modifier.fillMaxWidth().heightIn(max = 420.dp),
                    contentScale = ContentScale.Fit
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    previewBitmap?.recycle()
                    previewBitmap = null
                }) { Text("Close", color = VeyloraGold) }
            }
        )
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = VeyloraSurface,
        title = { Text(if (account == null) "Add account" else "Edit account", color = VeyloraText) },
        text = {
            Column(
                Modifier.fillMaxWidth().heightIn(max = 520.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(9.dp)
            ) {
                OutlinedTextField(title, { title = it; error = null }, label = { Text("Account name *") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(username, { username = it }, label = { Text("Username / Email") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(password, { password = it }, label = { Text("Password") },
                    singleLine = true, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth())
                TextButton(onClick = {
                    password = generateSecurePassword(20)
                }) { Text("Generate secure password", color = VeyloraGold) }
                OutlinedTextField(website, { website = it }, label = { Text("Website") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())

                Box(Modifier.fillMaxWidth()) {
                    OutlinedTextField(
                        value = category,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Category") },
                        modifier = Modifier.fillMaxWidth(),
                        trailingIcon = { TextButton(onClick = { categoryExpanded = true }) { Text("Choose", color = VeyloraGold) } }
                    )
                    DropdownMenu(
                        expanded = categoryExpanded,
                        onDismissRequest = { categoryExpanded = false }
                    ) {
                        categories.forEach { option ->
                            DropdownMenuItem(
                                text = { Text(option) },
                                onClick = { category = option; categoryExpanded = false }
                            )
                        }
                    }
                }

                OutlinedTextField(notes, { notes = it }, label = { Text("Notes") },
                    modifier = Modifier.fillMaxWidth(), minLines = 2, maxLines = 4)

                Text("CUSTOM FIELDS", color = VeyloraGold, fontSize = 10.sp,
                    letterSpacing = 1.5.sp, fontWeight = FontWeight.SemiBold)
                customFields.forEachIndexed { index, field ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = VeyloraBlack),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(Modifier.padding(10.dp)) {
                            OutlinedTextField(
                                value = field.label,
                                onValueChange = { value ->
                                    customFields[index] = field.copy(label = value)
                                },
                                label = { Text("Field name") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = field.value,
                                onValueChange = { value ->
                                    customFields[index] = field.copy(value = value)
                                },
                                label = { Text("Field value") },
                                modifier = Modifier.fillMaxWidth()
                            )
                            TextButton(onClick = { customFields.removeAt(index) }) {
                                Text("Remove field", color = Color(0xFFFF8A80))
                            }
                        }
                    }
                }
                TextButton(
                    onClick = {
                        if (customFields.size < 30) {
                            customFields.add(AccountCustomField(label = "", value = ""))
                        }
                    },
                    enabled = customFields.size < 30
                ) {
                    Text("＋ Add custom field", color = VeyloraGold)
                }
                Text("SCREENSHOT ATTACHMENTS", color = VeyloraGold, fontSize = 10.sp,
                    letterSpacing = 1.5.sp, fontWeight = FontWeight.SemiBold)
                if (account == null) {
                    Text("Save this account first to attach screenshots.", color = VeyloraMuted, fontSize = 11.sp)
                } else {
                    attachments.forEach { attachment ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(attachment.displayName, color = VeyloraText, fontSize = 12.sp,
                                    maxLines = 1)
                                Text(
                                    "${attachment.mimeType} • ${(attachment.sizeBytes / 1024).coerceAtLeast(1)} KB",
                                    color = VeyloraMuted, fontSize = 10.sp
                                )
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                TextButton(onClick = {
                                    scope.launch {
                                        try {
                                            val bytes = withContext(Dispatchers.IO) {
                                                AccountVaultStore.readScreenshot(context, account.id, attachment.id)
                                            }
                                            try {
                                                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                                                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                                                if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                                                    throw IllegalStateException("Screenshot image is invalid.")
                                                }
                                                var sampleSize = 1
                                                while (bounds.outWidth / sampleSize > 1600 ||
                                                    bounds.outHeight / sampleSize > 1600) {
                                                    sampleSize *= 2
                                                }
                                                val bitmap = BitmapFactory.decodeByteArray(
                                                    bytes, 0, bytes.size,
                                                    BitmapFactory.Options().apply { inSampleSize = sampleSize }
                                                ) ?: throw IllegalStateException("Could not preview this screenshot.")
                                                previewBitmap?.recycle()
                                                previewBitmap = bitmap
                                                previewName = attachment.displayName
                                                error = null
                                            } finally {
                                                bytes.fill(0)
                                            }
                                        } catch (failure: Exception) {
                                            error = failure.message ?: "Could not open this encrypted screenshot."
                                        }
                                    }
                                }) { Text("View", color = VeyloraGold) }
                                TextButton(onClick = {
                                    scope.launch {
                                        try {
                                            withContext(Dispatchers.IO) {
                                                AccountVaultStore.removeScreenshot(context, account.id, attachment.id)
                                            }
                                            attachments.remove(attachment)
                                            error = null
                                        } catch (failure: Exception) {
                                            error = failure.message ?: "Could not remove this screenshot."
                                        }
                                    }
                                }) { Text("Remove", color = Color(0xFFFF8A80)) }
                            }
                        }
                    }
                    TextButton(
                        onClick = { screenshotPicker.launch("image/*") },
                        enabled = attachments.size < 20
                    ) {
                        activity?.beginExternalPicker()
                        screenshotPicker.launch("image/*")
                    }
                    Text("JPEG, PNG or WebP • Maximum 8 MB each • Encrypted on this device",
                        color = VeyloraMuted, fontSize = 10.sp, lineHeight = 14.sp)
                }
                if (error != null) Text(error!!, color = Color(0xFFFF8A80), fontSize = 11.sp)
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val nonEmptyFields = customFields.filter { it.label.isNotBlank() || it.value.isNotBlank() }
                when {
                    title.isBlank() -> error = "Enter an account name."
                    title.length > 200 || website.length > 2048 ||
                        username.length > 100000 || password.length > 100000 ||
                        notes.length > 100000 || category.isBlank() || category.length > 100 ->
                        error = "One or more fields exceed the allowed length."
                    nonEmptyFields.any { it.label.isBlank() } ->
                        error = "Give every custom field a name."
                    nonEmptyFields.any { it.label.length > 100 || it.value.length > 100000 } ->
                        error = "A custom field exceeds the allowed length."
                    else -> onSave(
                        VaultAccount(
                            id = account?.id ?: java.util.UUID.randomUUID().toString(),
                            title = title.trim(),
                            username = username,
                            password = password,
                            website = website.trim(),
                            notes = notes,
                            category = category,
                            customFields = nonEmptyFields,
                            attachments = account?.attachments.orEmpty(),
                            isFavorite = account?.isFavorite ?: false,
                            createdAt = account?.createdAt ?: System.currentTimeMillis(),
                            updatedAt = System.currentTimeMillis()
                        )
                    )
                }
            }) { Text("Save securely", color = VeyloraGold) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel", color = VeyloraMuted) }
        }
    )
}

@Composable
private fun SettingsScreen(
    biometricEnabled: Boolean,
    onEnableBiometric: (((Boolean, String?) -> Unit) -> Unit),
    onDisableBiometric: () -> Unit,
    pinEnabled: Boolean,
    onEnablePin: (String) -> Boolean,
    onDisablePin: () -> Unit
) {
    var showPinDialog by remember { mutableStateOf(false) }
    var pinInput by remember { mutableStateOf("") }
    var pinConfirmation by remember { mutableStateOf("") }
    var pinMessage by remember { mutableStateOf<String?>(null) }
    var pinIsEnabled by remember { mutableStateOf(pinEnabled) }
    var biometricIsEnabled by remember { mutableStateOf(biometricEnabled) }
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(22.dp)
    ) {
        Text("Settings", color = VeyloraText, fontSize = 27.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text("Manage your Veylora experience.", color = VeyloraMuted, fontSize = 13.sp)
        Spacer(Modifier.height(24.dp))
        SettingsItem("Security", "Master password protection enabled", "◈")
        Spacer(Modifier.height(8.dp))
        Text(
            if (pinIsEnabled) "App PIN is enabled. Five incorrect attempts disable PIN unlock and require the master password."
            else "Set a 6–12 digit app PIN for convenient local unlock.",
            color = VeyloraMuted, fontSize = 12.sp, lineHeight = 17.sp
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(
                onClick = { pinInput = ""; pinConfirmation = ""; pinMessage = null; showPinDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = VeyloraGold, contentColor = VeyloraBlack)
            ) { Text(if (pinIsEnabled) "Change PIN" else "Enable PIN") }
            if (pinIsEnabled) {
                TextButton(onClick = { onDisablePin(); pinIsEnabled = false; pinMessage = "App PIN disabled." }) {
                    Text("Disable", color = VeyloraGold)
                }
            }
        }
        if (pinMessage != null) Text(pinMessage!!, color = VeyloraMuted, fontSize = 11.sp)
        Spacer(Modifier.height(12.dp))
        Text(
            if (biometricIsEnabled) "Biometric unlock is enabled on this device."
            else "Enable strong biometric unlock for quicker access.",
            color = VeyloraMuted, fontSize = 12.sp, lineHeight = 17.sp
        )
        Spacer(Modifier.height(8.dp))
        if (biometricIsEnabled) {
            TextButton(onClick = { onDisableBiometric(); biometricIsEnabled = false }) {
                Text("Disable biometric unlock", color = VeyloraGold)
            }
        } else {
            var biometricMessage by remember { mutableStateOf<String?>(null) }
            Button(
                onClick = { onEnableBiometric { success, message ->
                    biometricMessage = if (success) "Biometric unlock enabled." else message
                    if (success) biometricIsEnabled = true
                } },
                colors = ButtonDefaults.buttonColors(containerColor = VeyloraGold, contentColor = VeyloraBlack)
            ) {
                Text("Enable biometric unlock")
            }
            if (biometricMessage != null) {
                Text(biometricMessage!!, color = VeyloraMuted, fontSize = 11.sp)
            }
        }
        SettingsItem("Appearance", "Luxury dark theme", "◐")
        SettingsItem("Backup & restore", "Encrypted backup options", "↗")
        SettingsItem("About Veylora", "Version 1.0.0 · Your Digital Life, Secured.", "ⓘ")
        Spacer(Modifier.height(20.dp))
        Text("PIN and biometric unlock are convenience methods only. Your master password remains the recovery method.",
            color = VeyloraMuted, fontSize = 11.sp, lineHeight = 16.sp)
    }
    if (showPinDialog) {
        AlertDialog(
            onDismissRequest = { showPinDialog = false; pinInput = ""; pinConfirmation = "" },
            containerColor = VeyloraSurface,
            title = { Text(if (pinIsEnabled) "Change app PIN" else "Set app PIN", color = VeyloraText) },
            text = {
                Column {
                    Text("Choose 6–12 digits. This PIN unlocks only this device and is not your master password.",
                        color = VeyloraMuted, fontSize = 12.sp, lineHeight = 17.sp)
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = pinInput,
                        onValueChange = { if (it.length <= 12 && it.all(Char::isDigit)) pinInput = it },
                        singleLine = true,
                        label = { Text("New PIN") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = pinConfirmation,
                        onValueChange = { if (it.length <= 12 && it.all(Char::isDigit)) pinConfirmation = it },
                        singleLine = true,
                        label = { Text("Confirm PIN") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)
                    )
                    if (pinMessage != null) {
                        Spacer(Modifier.height(8.dp))
                        Text(pinMessage!!, color = Color(0xFFFF8A80), fontSize = 11.sp)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    pinMessage = when {
                        pinInput.length !in 6..12 -> "PIN must contain 6–12 digits."
                        pinInput != pinConfirmation -> "The PINs do not match."
                        !onEnablePin(pinInput) -> "Could not enable PIN. Try again or use your master password."
                        else -> null
                    }
                    if (pinMessage == null) {
                        pinIsEnabled = true
                        pinInput = ""; pinConfirmation = ""; showPinDialog = false
                    }
                }) { Text("Save PIN", color = VeyloraGold) }
            },
            dismissButton = {
                TextButton(onClick = { showPinDialog = false; pinInput = ""; pinConfirmation = "" }) {
                    Text("Cancel", color = VeyloraMuted)
                }
            }
        )
    }
}

@Composable
private fun SettingsItem(title: String, subtitle: String, symbol: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)
            .background(VeyloraSurface, RoundedCornerShape(15.dp)).padding(15.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(symbol, color = VeyloraGold, fontSize = 20.sp)
        Spacer(Modifier.size(14.dp))
        Column {
            Text(title, color = VeyloraText, fontSize = 14.sp, fontWeight = FontWeight.Medium)
            Spacer(Modifier.height(3.dp))
            Text(subtitle, color = VeyloraMuted, fontSize = 11.sp)
        }
    }
}
