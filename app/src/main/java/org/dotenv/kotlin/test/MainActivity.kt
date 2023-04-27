package org.dotenv.kotlin.test

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import org.dotenv.vault.dotenvVault

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val vaultKey = BuildConfig.DOTENV_KEY
        println("initializing vault with key: ${vaultKey.substring(0, 6)}")
        val vault = dotenvVault(vaultKey) {
            directory = "/assets"
            filename = "env.vault"
        }

        val decryptedValue = vault["MY_TEST_EV1"]
        println("dotenv decrypted value: ${decryptedValue}")
    }
}