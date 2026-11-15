package com.unlogistix.veylora

import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager
import androidx.core.content.ContextCompat
import androidx.activity.compose.setContent
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.unlogistix.veylora.security.InvalidMasterPasswordException
import com.unlogistix.veylora.security.BiometricVaultUnlock
import com.unlogistix.veylora.security.VaultCrypto
import com.unlogistix.veylora.security.VaultSession
import javax.crypto.Cipher
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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


    fun enableBiometricUnlock(onResult: (Boolean, String?) -> Unit) {
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

    override fun onStop() {
        VaultSession.lock()
        sessionVersion++
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
        VaultGateScreen(initialized = initialized, biometricAvailable = BiometricVaultUnlock.isEnabled(context), activity = activity, onUnlocked = { unlocked = true })
    }
}

@Composable
private fun VeyloraDashboard(activity: MainActivity?) {
    var selectedTab by remember { mutableStateOf(VeyloraTab.HOME) }
    var showVaultNotice by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = VeyloraBlack
    ) {
        androidx.compose.material3.Scaffold(
            containerColor = VeyloraBlack,
            bottomBar = {
                NavigationBar(
                    containerColor = Color(0xFF111113),
                    contentColor = VeyloraText
                ) {
                    VeyloraTab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = selectedTab == tab,
                            onClick = { selectedTab = tab },
                            icon = {
                                Text(
                                    text = tab.symbol,
                                    fontSize = 21.sp,
                                    color = if (selectedTab == tab) VeyloraGold else VeyloraMuted
                                )
                            },
                            label = {
                                Text(
                                    text = tab.label,
                                    fontSize = 11.sp
                                )
                            }
                        )
                    }
                }
            }
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                when (selectedTab) {
                    VeyloraTab.HOME -> HomeScreen(onAddClick = { showVaultNotice = true })
                    VeyloraTab.FAVORITES -> EmptyCollectionScreen(
                        title = "Your favorites",
                        message = "Accounts you mark as favorites will appear here."
                    )
                    VeyloraTab.SEARCH -> SearchScreen(
                        query = searchQuery,
                        onQueryChange = { searchQuery = it }
                    )
                    VeyloraTab.SETTINGS -> SettingsScreen(
                        biometricEnabled = activity?.let { BiometricVaultUnlock.isEnabled(it) } == true,
                        onEnableBiometric = { callback -> activity?.enableBiometricUnlock(callback) },
                        onDisableBiometric = { activity?.let { BiometricVaultUnlock.disable(it) } }
                    )
                }
            }
        }
    }

    if (showVaultNotice) {
        AlertDialog(
            onDismissRequest = { showVaultNotice = false },
            containerColor = VeyloraSurface,
            title = {
                Text("Account storage is next", color = VeyloraText, fontWeight = FontWeight.SemiBold)
            },
            text = {
                Text(
                    "Master-password protection is active, but account storage is still under development. Do not enter real account passwords yet.",
                    color = VeyloraMuted
                )
            },
            confirmButton = {
                TextButton(onClick = { showVaultNotice = false }) {
                    Text("Got it", color = VeyloraGold)
                }
            }
        )
    }
}


@Composable
private fun VaultGateScreen(initialized: Boolean, biometricAvailable: Boolean, activity: MainActivity?, onUnlocked: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
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
private fun HomeScreen(onAddClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 22.dp, vertical = 20.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("VEY LORA".replace(" ", ""), color = VeyloraText, fontSize = 19.sp,
                    letterSpacing = 3.sp, fontWeight = FontWeight.SemiBold)
                Text("YOUR PRIVATE SPACE", color = VeyloraMuted, fontSize = 9.sp,
                    letterSpacing = 2.sp)
            }
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .background(VeyloraSurface, CircleShape),
                contentAlignment = Alignment.Center
            ) {
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
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier.size(34.dp).background(Color(0xFF342B1C), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("✦", color = VeyloraGold, fontSize = 18.sp)
                    }
                    Spacer(Modifier.size(10.dp))
                    Text("VAULT STATUS", color = VeyloraGold, fontSize = 11.sp,
                        letterSpacing = 1.8.sp, fontWeight = FontWeight.SemiBold)
                }
                Spacer(Modifier.height(18.dp))
                Text("Encrypted vault ready", color = VeyloraText, fontSize = 21.sp,
                    fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp))
                Text("Your master password protects a randomly generated vault key. Secure account storage is the next milestone.",
                    color = VeyloraMuted, fontSize = 13.sp, lineHeight = 19.sp)
                Spacer(Modifier.height(18.dp))
                Button(
                    onClick = onAddClick,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = VeyloraGold,
                        contentColor = VeyloraBlack
                    ),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("＋   Add your first account", fontWeight = FontWeight.SemiBold)
                }
            }
        }

        Spacer(Modifier.height(22.dp))
        Text("OVERVIEW", color = VeyloraMuted, fontSize = 11.sp,
            letterSpacing = 1.8.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OverviewCard("0", "ACCOUNTS", Modifier.weight(1f))
            OverviewCard("0", "FAVORITES", Modifier.weight(1f))
        }

        Spacer(Modifier.height(26.dp))
        Text("CATEGORIES", color = VeyloraMuted, fontSize = 11.sp,
            letterSpacing = 1.8.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(12.dp))
        CategoryRow("◈", "Social media", "Facebook · Instagram · TikTok")
        CategoryRow("✉", "Email & Google", "Gmail · Microsoft · Other email")
        CategoryRow("◇", "Finance", "Banking · Payments")
        CategoryRow("▣", "Gaming & more", "Games · Websites · Applications")
        Spacer(Modifier.height(22.dp))
        Text("Veylora is currently in development. No account data is stored in this build.",
            color = VeyloraMuted, fontSize = 11.sp, lineHeight = 16.sp)
        Spacer(Modifier.height(12.dp))
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
private fun SearchScreen(query: String, onQueryChange: (String) -> Unit) {
    Column(Modifier.fillMaxSize().padding(22.dp)) {
        Text("Search", color = VeyloraText, fontSize = 27.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text("Find an account in your vault.", color = VeyloraMuted, fontSize = 13.sp)
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
        Spacer(Modifier.height(26.dp))
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Text(
                if (query.isBlank()) "No accounts to search yet." else "No matches — your vault is empty.",
                color = VeyloraMuted,
                fontSize = 13.sp
            )
        }
    }
}

@Composable
private fun SettingsScreen(
    biometricEnabled: Boolean,
    onEnableBiometric: (((Boolean, String?) -> Unit) -> Unit),
    onDisableBiometric: () -> Unit
) {
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
            if (biometricEnabled) "Biometric unlock is enabled on this device."
            else "Enable strong biometric unlock for quicker access.",
            color = VeyloraMuted, fontSize = 12.sp, lineHeight = 17.sp
        )
        Spacer(Modifier.height(8.dp))
        if (biometricEnabled) {
            TextButton(onClick = onDisableBiometric) {
                Text("Disable biometric unlock", color = VeyloraGold)
            }
        } else {
            var biometricMessage by remember { mutableStateOf<String?>(null) }
            Button(
                onClick = { onEnableBiometric { success, message ->
                    biometricMessage = if (success) "Biometric unlock enabled." else message
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
        Text("PIN, biometrics, encrypted account storage and recovery are still being developed.",
            color = VeyloraMuted, fontSize = 11.sp, lineHeight = 16.sp)
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
