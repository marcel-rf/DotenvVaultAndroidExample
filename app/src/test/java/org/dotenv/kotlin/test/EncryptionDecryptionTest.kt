package org.dotenv.kotlin.test

import org.junit.Assert.*
import org.junit.Test
import java.nio.charset.Charset
import java.security.Key
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */

/**
 *
 */
const val KEY_BYTES = 32
const val AUTH_TAG_BYTES = 16
const val NONCE_BYTES = 12

private const val ALGORITHM = "AES"

class ProvidedKey: Key {
    override fun getAlgorithm(): String {
        return ALGORITHM
    }

    override fun getFormat(): String {
        return "RAW"
    }

    override fun getEncoded(): ByteArray {
        val sampleKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        return sampleKey.encodeToByteArray()
    }

}

class EncryptionDecryptionTest {

    private val DEFAULT_IV: IvParameterSpec =
        IvParameterSpec(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    fun encryptAESGCM256(plaintext: ByteArray): ByteArray {
        // recommended that you use the value specified here.
        //val plaintext: ByteArray = ...
        val keygen = KeyGenerator.getInstance(ALGORITHM)
        keygen.init(256)
        val key: SecretKey = keygen.generateKey()
        println("key algo: ${key.algorithm} format: ${key.format} encoded: ${key.encoded}")


        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val ciphertext: ByteArray = cipher.doFinal(plaintext)
        println("cipherText: ${ciphertext}")
        val iv: ByteArray = cipher.iv
        return iv
    }

    private fun getHash(algorithm: String, data: ByteArray): ByteArray {
        return try {
            val digest: MessageDigest = MessageDigest.getInstance(algorithm)
            digest.update(data)
            digest.digest()
        } catch (ex: java.lang.Exception) {
            throw RuntimeException(ex.message)
        }
    }

    private fun getHash(algorithm: String, text: String): ByteArray {
        return try {
            getHash(algorithm, text.toByteArray(charset("UTF-8")))
        } catch (ex: java.lang.Exception) {
            throw java.lang.RuntimeException(ex.message)
        }
    }

    private fun decrypt(
        password: String,
        key: Key,
        iv: ByteArray,
        encryptedData: ByteArray
    ): ByteArray {
        val paramSpec = GCMParameterSpec(128, encryptedData)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, paramSpec)
        return cipher.doFinal(encryptedData)
    }

    fun decryptAESGCM256(plaintext: ByteArray, keyString: String): ByteArray? {
        // recommended that you use the value specified here.
        //val plaintext: ByteArray = ...
        val keygen = KeyGenerator.getInstance(ALGORITHM)
        keygen.init(256)
        val key: SecretKey = keygen.generateKey()
        println("key algo: ${key.algorithm} format: ${key.format} encoded: ${key.encoded}")


        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        //val ivSpec = IvParameterSpec(iv)
//        val secretKeySpec = SecretKeySpec(getHash("SHA-256", keyString), ALGORITHM)
//        val secretAlgoSpec = AlgorithmParameterSpec(getHash("SHA-256", keyString), ALGORITHM)
//
//                cipher.init(Cipher.DECRYPT_MODE, key, secretKeySpec)
//        val ciphertext: ByteArray = cipher.doFinal(plaintext)
//        val iv: ByteArray = cipher.iv
//        println("decryptedText: ${ciphertext}")
//        val decryptedUTFString = String(cipher.iv, Charset.forName("UTF-8"))
//        return iv
        return null
    }

    @Throws(Exception::class)
    private fun getRawKey(seed: ByteArray): ByteArray? {
        val keygen = KeyGenerator.getInstance(ALGORITHM)
        val random = SecureRandom.getInstance("SHA1PRNG")
        random.setSeed(seed)
        keygen.init(128, random) // 192 and 256 bits may not be available
        val key = keygen.generateKey()
        return key.encoded
    }

    fun generateKey(): Key {
        val keygen = KeyGenerator.getInstance(ALGORITHM)
        keygen.init(256)
        val key: SecretKey = keygen.generateKey()
        return key
    }

    fun cipherAESGCM256(plaintext: ByteArray, key: Key): ByteArray {
        // recommended that you use the value specified here.
        //val plaintext: ByteArray = ...
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val ciphertext: ByteArray = cipher.doFinal(plaintext)
        val iv: ByteArray = cipher.iv
        return iv
    }

    private fun decodeKey(key: String): String {
        return Base64.getDecoder().decode(key).toString()
        //return Buffer.from(key, 'hex')
    }

    fun generateNonce(): ByteArray {
        val sr = SecureRandom()
        val nonceArray = ByteArray(NONCE_BYTES)
        sr.nextBytes(nonceArray)
        return nonceArray
    }

    fun encrypt(key: String, message: String): String {
        // set up key and nonce
        val decodedKey = decodeKey(key)
        println("decoded key from $key -> $decodedKey")

        val nonce = generateNonce()
        println("nonce: ${nonce}")

        // set up cipher
        //val cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

        return "TODO"
    }

    fun decrypt(key: String, ciphertext: String): String {
        throw NotImplementedError()
    }

    @Test
    fun verifyEncryptionDecryptionForHello() {
        val key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val message = "HELLO"

        val ciphertext = encrypt(key, message)
        val message2 = decrypt(key, ciphertext)

        /* message 2 should equal message */
        assertEquals(message, message2)
    }

    @Test
    fun verifyAESGCMEncryption() {
        val key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val message = "HELLO"
        val encrypted = encryptAESGCM256(message.toByteArray())
        val resultStr: String = Base64.getEncoder().encodeToString(encrypted)
        println("encrypted msg: ${encrypted} base64: ${resultStr}")
    }

    @Test
    fun verifyAESGCMEncryptionWithKey() {
        val keyString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
//        val keyString = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val message = "HELLO"
        val key = generateKey()
        val encrypted = cipherAESGCM256(message.toByteArray(), key)
        val resultStr: String = Base64.getEncoder().encodeToString(encrypted)
        println("encrypted msg: ${encrypted} base64: ${resultStr}")

        val decryptedMessage = decrypt(keyString, key, encrypted, encrypted)
        val decryptedStr: String = Base64.getEncoder().encodeToString(decryptedMessage)
        println("decryptedMessage: ${decryptedMessage} base64: ${decryptedStr}")
    }
}