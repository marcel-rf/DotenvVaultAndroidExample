package org.dotenv.kotlin.test

import org.junit.Test
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


data class CipherResult(
    val encryptedText: ByteArray,
    val iv: ByteArray
)

fun ByteArray.toHexString() = this.joinToString("") { String.format("%02X", (it.toInt() and 0xFF)) }
fun String.byteArrayFromHexString() = this.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun String.fromHexString2()=this.chunked(2).map { it.toInt(16).toChar() }.toCharArray().joinToString()

private const val ALGORITHM = "AES"

class AESGCMCipher {

    fun createKey(): SecretKey {
        val secureKeyRandomness: SecureRandom = SecureRandom.getInstanceStrong()
        val AES_keyInstance: KeyGenerator = KeyGenerator.getInstance(ALGORITHM)
        AES_keyInstance.init(128, secureKeyRandomness)
        val secretKey: SecretKey = AES_keyInstance.generateKey()
        return secretKey
    }

    fun create256Key(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM)
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()
        return secretKey
    }

    private fun getSecureRandomKey(cipher: String, keySize: Int): SecretKey {
        val secureRandomKeyBytes = ByteArray(keySize / 8)
        val secureRandom = SecureRandom()
        secureRandom.nextBytes(secureRandomKeyBytes)
        return SecretKeySpec(secureRandomKeyBytes, cipher)
    }

    fun createKeyFromBytes(keyBytes: ByteArray): SecretKey {
        return SecretKeySpec(keyBytes, ALGORITHM)
    }

    fun createKeyAESGCM(keyString: String): SecretKey {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val SALT = "abcdefg"
        val spec: KeySpec = PBEKeySpec(keyString.toCharArray(), SALT.toByteArray(), 65536, 256)
        val tmp = factory.generateSecret(spec)
        val secretKey = SecretKeySpec(tmp.encoded, ALGORITHM)
        return secretKey
    }

    fun encrypt(cleartext: String, secretKey: SecretKey): CipherResult {
        val clearTextbytes = cleartext.toByteArray(charset("UTF-8"))

        val AES_cipherInstance: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
        AES_cipherInstance.init(Cipher.ENCRYPT_MODE, secretKey)
        val encryptedText: ByteArray = AES_cipherInstance.doFinal(clearTextbytes)

        val iv: ByteArray = AES_cipherInstance.iv
        return CipherResult(encryptedText, iv)
    }

    fun decrypt(encryptedText: ByteArray, secretKey: SecretKey): String {
        val AES_cipherInstance = Cipher.getInstance("AES/GCM/NoPadding")
        val params = GCMParameterSpec(128, encryptedText, 0, 12)
        AES_cipherInstance.init(Cipher.DECRYPT_MODE, secretKey, params)
        val decryptedText =
            AES_cipherInstance.doFinal(encryptedText, 12, encryptedText.size - 12)
        return String(decryptedText, Charset.forName("UTF-8"))
    }

    //aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
//aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    @Test
    fun verifyStuff() {
        val message = "HELLO"
        val keyString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        val fromHEx = keyString.byteArrayFromHexString()
        val toHex = fromHEx.toHexString()
        println("decoded key ${keyString} fromHEx: ${fromHEx} toHex: ${toHex} fromHEx length: ${fromHEx.size}")

        //val keyString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        println("message: $message")
        val messageBytes = message.toByteArray(charset("UTF-8"))

        val secretKey0 = getSecureRandomKey(ALGORITHM, 256)
        println("key0 bytes: ${secretKey0.encoded} size: ${secretKey0.encoded.size} format: ${secretKey0.format}")

        val secretKey2 = create256Key()
        println("key2 bytes: ${secretKey2.encoded} size: ${secretKey2.encoded.size} format: ${secretKey2.format}")

        //val keyBytes = keyString.toByteArray()
//        val keyBytes = keyString.toCharArray()
        println("key bytes: ${fromHEx} lenght: ${fromHEx.size}")
        val secretKey = createKeyFromBytes(fromHEx)

        println("key1 bytes: ${secretKey.encoded} size: ${secretKey.encoded.size} format: ${secretKey.format}")
        //val secretKey = createKeyAESGCM(keyString)


        val encryptedResult = encrypt(message, secretKey)
        val base64Encrypted = Base64.getEncoder().encode(encryptedResult.encryptedText)
        println("encrypted text = ${encryptedResult.encryptedText} -> ${base64Encrypted}")

        val messagePart = ByteArray(12 + messageBytes.size + 16)
        System.arraycopy(encryptedResult.iv, 0, messagePart, 0, 12)
        System.arraycopy(encryptedResult.encryptedText, 0, messagePart, 12, encryptedResult.encryptedText.size)

        val decrypted = decrypt(messagePart, secretKey)
        println("decrypted text: ${decrypted}")
    }
}