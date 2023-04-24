package org.dotenv.kotlin.test

import android.util.Base64
import org.junit.Test
import java.nio.charset.Charset
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESEncryption {

    var ivBytes = byteArrayOf(
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
    )

    data class CipherResult(
        val cipherText: String,
        val encryptedText: ByteArray,
        val iv: ByteArray
    )

    fun encryptMsg(message: String, secret: SecretKey): CipherResult {
        var cipher: Cipher? = null
        cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secret)
        val cipherText: ByteArray = cipher.doFinal(message.toByteArray(charset("UTF-8")))
        return CipherResult(java.util.Base64.getEncoder().encodeToString(cipherText), cipherText, cipher.iv)
        //return Base64.encodeToString(cipherText, Base64.NO_WRAP)
    }

    fun decryptMsg(encryptedText: ByteArray, secret: SecretKey): String {
        var cipher: Cipher? = null
        cipher = Cipher.getInstance("AES/GCM/NoPadding")

        val params = GCMParameterSpec(128, encryptedText, 0, 12)
        //val ivSpec: AlgorithmParameterSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, secret, params)
        //val decode: ByteArray = Base64.decode(cipherText, Base64.NO_WRAP)
        return String(cipher.doFinal(encryptedText), Charset.forName("UTF-8"))
    }

    fun generateKey(key: String): SecretKey {

//        val secretContent: ByteArray = Hex.decodeHex(key.toCharArray())
//        val secretKey = SecretKeySpec(secret, "AES")

        val keyArray = key.toByteArray(charset("UTF-8"))
        val secret: SecretKeySpec
//        val keyArray = key.toByteArray()
        println("key byte array length ${keyArray.size}")
        //secret = SecretKeySpec(keyArray, 0, 64, "AES")
        secret = SecretKeySpec(keyArray, "AES")
        return secret
    }



    @Test
    fun verifyAESGCMEncryptionWithKey() {
        val keyString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
//        val keyString = "e8ffc7e56311679f12b6fc91aa77a5eb"
//        val keyString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        //val keyString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val message = "HELLO"
        val key = generateKey(keyString)
        val encrypted = encryptMsg(message, key)
        //val resultStr: String = java.util.Base64.getEncoder().encodeToString(encrypted)
        println("encrypted msg: ${encrypted.cipherText} base64: ${encrypted.iv}")

        val decryptedMessage = decryptMsg(encrypted.encryptedText, key)
        println("decryptedMessage: ${decryptedMessage}")
    }
}