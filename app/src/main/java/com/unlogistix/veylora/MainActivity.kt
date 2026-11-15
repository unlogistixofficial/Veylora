package com.unlogistix.veylora

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContent {
            VeyloraTheme {
                VeyloraApp()
            }
        }
    }
}

@Composable
private fun VeyloraApp() {
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
                    VeyloraTab.SETTINGS -> SettingsScreen()
                }
            }
        }
    }

    if (showVaultNotice) {
        AlertDialog(
            onDismissRequest = { showVaultNotice = false },
            containerColor = VeyloraSurface,
            title = {
                Text("Vault setup is next", color = VeyloraText, fontWeight = FontWeight.SemiBold)
            },
            text = {
                Text(
                    "The secure vault and encryption layer are not implemented yet. Please don't enter or save real passwords in this build.",
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
                Text("Not initialized", color = VeyloraText, fontSize = 21.sp,
                    fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp))
                Text("Your secure vault will be ready after master password and encryption setup.",
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
private fun SettingsScreen() {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(22.dp)
    ) {
        Text("Settings", color = VeyloraText, fontSize = 27.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Text("Manage your Veylora experience.", color = VeyloraMuted, fontSize = 13.sp)
        Spacer(Modifier.height(24.dp))
        SettingsItem("Security", "Master password, PIN and biometrics", "◈")
        SettingsItem("Appearance", "Luxury dark theme", "◐")
        SettingsItem("Backup & restore", "Encrypted backup options", "↗")
        SettingsItem("About Veylora", "Version 1.0.0 · Your Digital Life, Secured.", "ⓘ")
        Spacer(Modifier.height(20.dp))
        Text("Security features will be enabled in upcoming development steps.",
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
