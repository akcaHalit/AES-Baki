package com.example.aesogreniyorum

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESUtil2 {



    private val keyGenerator: KeyGenerator = KeyGenerator.getInstance("AES")
    private val secretKey: SecretKey = keyGenerator.generateKey()
    private val IV = ByteArray(16)

    init {
        // Initialize IV
        val random = SecureRandom()
        random.nextBytes(IV)
    }

    fun encrypt(plaintext: String): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val keySpec = SecretKeySpec(secretKey.encoded, "AES")
        val ivSpec = IvParameterSpec(IV)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(plaintext.toByteArray())
    }

    fun decrypt(cipherText: ByteArray): String {
        try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val keySpec = SecretKeySpec(secretKey.encoded, "AES")
            val ivSpec = IvParameterSpec(IV)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            return String(cipher.doFinal(cipherText))
        } catch (e: Exception) {
            e.printStackTrace()
            println("e: $e")
        }
        return ""
    }
}


/*
class AESUtil2 {

    private val keyGenerator: KeyGenerator = KeyGenerator.getInstance("AES")
    private val secretKey: SecretKey = keyGenerator.generateKey()
    private val IV = ByteArray(16)

    init {
        // Initialize IV
        val random = SecureRandom()
        random.nextBytes(IV)
    }

    @SuppressLint("GetInstance")
    fun encrypt(plaintext: String): ByteArray {
        val cipher = Cipher.getInstance("AES")
        val keySpec = SecretKeySpec(secretKey.encoded, "AES")
        val ivSpec = IvParameterSpec(IV)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(plaintext.toByteArray())
    }

    @SuppressLint("GetInstance")
    fun decrypt(cipherText: ByteArray): String {
        try {
            val cipher = Cipher.getInstance("AES")
            println("AAAAAAAA")
            val keySpec = SecretKeySpec(secretKey.encoded, "AES")
            println("AAAAAAAA")
            val ivSpec = IvParameterSpec(IV)
            println("AAAAAAAA")
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            println("AAAAAAAA")
            val decryptedText = cipher.doFinal(cipherText)
            println("AAAAAAAA")
            return String(decryptedText)
        } catch (e: Exception) {
            e.printStackTrace()
            println("E: $e")
        }
        return ""
    }
}

 */