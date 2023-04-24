package org.dotenv.kotlin.test

import org.junit.Test
import java.io.UnsupportedEncodingException
import java.nio.charset.Charset
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec

class AESGCMCipher {
    fun encrypt(cleartext: String): String {
        try {
            // encoding format needs thought
            val clearTextbytes = cleartext.toByteArray(charset("UTF-8"))
            val secureKeyRandomness: SecureRandom = SecureRandom.getInstanceStrong()
            val AES_keyInstance: KeyGenerator = KeyGenerator.getInstance("AES")
            AES_keyInstance.init(128, secureKeyRandomness)
            val secretKey: SecretKey = AES_keyInstance.generateKey()
            val AES_cipherInstance: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
            AES_cipherInstance.init(Cipher.ENCRYPT_MODE, secretKey)
            val encryptedText: ByteArray = AES_cipherInstance.doFinal(clearTextbytes)

            val encryptedTextString = Base64.getEncoder().encode(encryptedText)
            println("encrypted text: ${encryptedTextString}")


            val iv: ByteArray = AES_cipherInstance.getIV()
            val message = ByteArray(12 + clearTextbytes.size + 16)
            System.arraycopy(iv, 0, message, 0, 12)
            System.arraycopy(encryptedText, 0, message, 12, encryptedText.size)

            return decrypt(message, secretKey)

        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
        } catch (e: BadPaddingException) {
            e.printStackTrace()
        } catch (e: UnsupportedEncodingException) {
            e.printStackTrace()
        }
        return "something went wrong with encrypt"
    } // encrypt.

    @Throws(Exception::class)
    fun decrypt(encryptedText: ByteArray, secretKey: SecretKey): String {
        try {
            val AES_cipherInstance = Cipher.getInstance("AES/GCM/NoPadding")
            val params = GCMParameterSpec(128, encryptedText, 0, 12)
            AES_cipherInstance.init(Cipher.DECRYPT_MODE, secretKey, params)
            val decryptedText =
                AES_cipherInstance.doFinal(encryptedText, 12, encryptedText.size - 12)
            return String(decryptedText, Charset.forName("UTF-8"))
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
        } catch (e: BadPaddingException) {
            e.printStackTrace()
        } catch (e: UnsupportedEncodingException) {
            e.printStackTrace()
        }
        return "something went wrong with decrypt"
    }


    @Test
    fun verifyStuff() {
        val encrypted: String = encrypt("My text")
        println("Decrypted text = ${encrypted}")
    }
}