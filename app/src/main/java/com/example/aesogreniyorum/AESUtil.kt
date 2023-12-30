package com.example.aesogreniyorum

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import com.google.gson.Gson
import java.security.Key
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec



@SuppressLint("CommitPrefEdits")
@RequiresApi(Build.VERSION_CODES.O)
class AESUtil (context: Context){

    private lateinit var sharedPreferences: SharedPreferences

    companion object {
        const val AES_ALGORITHM = "AES"
        const val AES_KEY_SIZE = 256
    }

    private var key: Key

    init {
        sharedPreferences = context.getSharedPreferences ("MyAppPreferences", Context. MODE_PRIVATE)
        key = generateKey()
        val editor = sharedPreferences.edit()
        val gson = Gson()
        val json = gson.toJson(key)
        editor.putString("MyObject", json)
        sharedPreferences.edit().putString("keyObject", json)
            .apply()
        //println("JSON: $json")
    }
    fun getKey() : Key{
        return key
    }


    /* HER SEFERİNDE KEY OLUŞTURMUYOR BEN OLUŞTURTUYOM
    fun keyFunction(){
        key = generateKey()
    }
    fun getKey() : Key{
        return key
    }
     */


    @RequiresApi(Build.VERSION_CODES.O)
    private fun generateKey(): Key {
        val keyGenerator: KeyGenerator = KeyGenerator.getInstance(AES_ALGORITHM)
        val secureRandom: SecureRandom = SecureRandom.getInstanceStrong()
        keyGenerator.init(AES_KEY_SIZE, secureRandom)
        return SecretKeySpec(keyGenerator.generateKey().encoded, AES_ALGORITHM)
    }

    @SuppressLint("GetInstance")
    fun encrypt(input: String): String {
        val cipher: Cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encryptedBytes: ByteArray = cipher.doFinal(input.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    @SuppressLint("GetInstance")
    fun decrypt(input: String): String {
        val cipher: Cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, key)
        val encryptedBytes: ByteArray = Base64.decode(input, Base64.DEFAULT)
        val decryptedBytes: ByteArray = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    }
}



/*
class AESUtil(private val context: Context) {
    private val sharedPreferences = context.getSharedPreferences("AES_SHARED_PREFERENCES", Context.MODE_PRIVATE)
    private val gson = Gson()

    private fun loadKeyFromSharedPreferences(): SecretKeySpec {
        val json = sharedPreferences.getString("keyObject", "")
        return if (json!!.isNotEmpty()) {
            gson.fromJson(json, SecretKeySpec::class.java)
        } else {
            generateKey()
        }
    }

    private fun generateKey(): SecretKeySpec {
        val key = ByteArray(16)
        val secureRandom = SecureRandom()
        secureRandom.nextBytes(key)
        return SecretKeySpec(key, "AES")
    }

    fun getKey(): SecretKeySpec {
        return loadKeyFromSharedPreferences()
    }

    @SuppressLint("GetInstance")
    fun encrypt(data: String): String {
        val secretKey = getKey()
        val cipher = Cipher.getInstance("AES/ECB/PCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return Base64.encodeToString(cipher.doFinal(data.toByteArray()), Base64.DEFAULT)
    }

    @SuppressLint("GetInstance")
    fun decrypt(encryptedData: String): String {
        val secretKey = getKey()
        val cipher = Cipher.getInstance("AES/ECB/PCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        return String(cipher.doFinal(Base64.decode(encryptedData, Base64.DEFAULT)))
    }
}
 */

/*
@RequiresApi(Build.VERSION_CODES.O)
class AESUtil(context: Context) {

    private lateinit var sharedPreferences: SharedPreferences

    companion object {
        const val AES_ALGORITHM = "AES"
        const val AES_KEY_SIZE = 256
    }

    private var key: Key

    init {
        sharedPreferences = context.getSharedPreferences("MyAppPreferences", Context.MODE_PRIVATE)
        key = loadKeyFromSharedPreferences()
    }

    fun getKey(): Key {
        return key
    }

    private fun loadKeyFromSharedPreferences(): Key {
        val json = sharedPreferences.getString("keyObject", "")
        return if (json!!.isNotEmpty()) {
            Gson().fromJson(json, Key::class.java)
        } else {
            generateKey()
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun generateKey(): Key {
        val keyGenerator: KeyGenerator = KeyGenerator.getInstance(AES_ALGORITHM)
        val secureRandom: SecureRandom = SecureRandom.getInstanceStrong()
        keyGenerator.init(AES_KEY_SIZE, secureRandom)
        val newKey = SecretKeySpec(keyGenerator.generateKey().encoded, AES_ALGORITHM)
        saveKeyToSharedPreferences(newKey)
        return newKey
    }

    private fun saveKeyToSharedPreferences(key: Key) {
        val gson = Gson()
        val json = gson.toJson(key)
        val editor = sharedPreferences.edit()
        editor.putString("keyObject", json)
        editor.apply()
    }

    @SuppressLint("GetInstance")
    fun encrypt(input: String): String {
        val cipher: Cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encryptedBytes: ByteArray = cipher.doFinal(input.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    @SuppressLint("GetInstance")
    fun decrypt(input: String): String {
        val cipher: Cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, key)
        val encryptedBytes: ByteArray = Base64.decode(input, Base64.DEFAULT)
        val decryptedBytes: ByteArray = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    }
}
 */