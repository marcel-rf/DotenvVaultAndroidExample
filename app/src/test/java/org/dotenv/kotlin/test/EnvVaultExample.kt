package org.dotenv.kotlin.test

import junit.framework.TestCase.assertEquals
import org.junit.Test
import java.nio.charset.Charset
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val ALGORITHM = "AES"


class EnvVaultExample {

    fun encrypt(secretKey: SecretKey, message: String): ByteArray {
        val messageByteArray = message.toByteArray(charset("UTF-8"))
        val aesCipher: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedMessage: ByteArray = aesCipher.doFinal(messageByteArray)
        val iv: ByteArray = aesCipher.iv
        val messageArray = iv + encryptedMessage
        return messageArray
    }

    fun decrypt(secretKey: SecretKey, encryptedMessage: ByteArray): String {
        val AES_cipherInstance = Cipher.getInstance("AES/GCM/NoPadding")
        val params = GCMParameterSpec(128, encryptedMessage, 0, 12)
        AES_cipherInstance.init(Cipher.DECRYPT_MODE, secretKey, params)
        val decryptedText =
            AES_cipherInstance.doFinal(encryptedMessage, 12, encryptedMessage.size - 12)
        return String(decryptedText, Charset.forName("UTF-8"))
    }

    fun createKeyFromBytes(keyBytes: ByteArray): SecretKey {
        return SecretKeySpec(keyBytes, ALGORITHM)
    }

    @Test
    fun verifyEncryptionDecryption() {
        val key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val message = "HELLO"

        val secretKey = createKeyFromBytes(key.fromHexString())

        val encryptedMessage = encrypt(secretKey, message)
        val decryptedMessage = decrypt(secretKey, encryptedMessage)

        assertEquals(message, decryptedMessage)
    }

    /**
     *  $cat .env.keys
        # DOTENV_KEYs (generated with npx dotenv-vault local build)
        DOTENV_KEY_DEVELOPMENT="dotenv://:key_14968ef8b3f56cbcfcaa83197efa34dba567e715e82ee69e050258a5522100f6@dotenv.local/vault/env.vault?environment=development"
        decryption key is: 14968ef8b3f56cbcfcaa83197efa34dba567e715e82ee69e050258a5522100f6

        $cat env.vault
        # env.vault (generated with npx dotenv-vault local build)
        DOTENV_VAULT_DEVELOPMENT="BuEEZbR/YQKR2Rj/bHvOQbv+gtIxPoik1BCqpvIdqmv/lhLr5PAKs0r9iIZ4dBWNlQE7WdQ8vak00cQuEV5/tmRUkN1g/HFcRuJMN5slL+xuUzK5YJo1XYRwsdHvMG2BUGST"
     *
     */
    @Test
    fun verifyDecryptionOfVaultWithActualKey() {
        val key = "14968ef8b3f56cbcfcaa83197efa34dba567e715e82ee69e050258a5522100f6"

        val encryptedMessage = "BuEEZbR/YQKR2Rj/bHvOQbv+gtIxPoik1BCqpvIdqmv/lhLr5PAKs0r9iIZ4dBWNlQE7WdQ8vak00cQuEV5/tmRUkN1g/HFcRuJMN5slL+xuUzK5YJo1XYRwsdHvMG2BUGST"

        val secretKey = createKeyFromBytes(key.fromHexString())
        println("encryptedMessage ${encryptedMessage}")
        val decodedEncryptedMessage = Base64.getDecoder().decode(encryptedMessage)
        val decryptedMessage = decrypt(secretKey, decodedEncryptedMessage)
        println("decryptedMessage ${decryptedMessage}")
        //assertEquals(message, decryptedMessage)
    }
}


fun String.fromHexString() = this.chunked(2).map { it.toInt(16).toByte() }.toByteArray()