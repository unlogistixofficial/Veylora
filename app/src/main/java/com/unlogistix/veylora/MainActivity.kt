package com.unlogistix.veylora

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.unlogistix.veylora.ui.theme.VeyloraTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContent {
            VeyloraTheme {
                VeyloraWelcomeScreen()
            }
        }
    }
}

@Composable
private fun VeyloraWelcomeScreen() {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFF0B0B0D)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFF0B0B0D))
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "V",
                    color = Color(0xFFD8B878),
                    fontSize = 58.sp,
                    fontWeight = FontWeight.Light
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "VEY LORA".replace(" ", ""),
                    color = Color(0xFFF4F0E8),
                    fontSize = 28.sp,
                    letterSpacing = 5.sp,
                    fontWeight = FontWeight.Medium
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Your Digital Life, Secured.",
                    color = Color(0xFFB8B2A7),
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(modifier = Modifier.height(28.dp))
                Text(
                    text = "Android foundation is ready",
                    color = Color(0xFFD8B878),
                    fontSize = 13.sp,
                    modifier = Modifier
                        .background(Color(0xFF191817), RoundedCornerShape(50))
                        .padding(horizontal = 16.dp, vertical = 9.dp)
                )
            }
        }
    }
}
