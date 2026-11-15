package com.unlogistix.veylora.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val VeyloraColorScheme = darkColorScheme(
    primary = VeyloraGold,
    onPrimary = VeyloraBlack,
    background = VeyloraBlack,
    onBackground = VeyloraText,
    surface = VeyloraSurface,
    onSurface = VeyloraText,
    secondary = VeyloraMuted
)

@Composable
fun VeyloraTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = VeyloraColorScheme,
        content = content
    )
}
