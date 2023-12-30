package com.example.aesogreniyorum

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.example.aesogreniyorum.databinding.ActivityMainBinding
import com.google.gson.Gson
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import org.mindrot.jbcrypt.BCrypt
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val sharedPreferences: SharedPreferences by lazy {
        getSharedPreferences("MyAppPreferences", Context.MODE_PRIVATE)
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)



        /*
        val aesUtil = AESUtil(applicationContext)

        val gson = Gson()
        val keyJson = sharedPreferences.getString("keyObject", null)
        val json = gson.fromJson(keyJson,Key::class.java)

        println("JSON: $json")
         */
        /*          HER SEFERİNDE KEY OLUŞTURMUYOR BEN OLUŞTURTUYOM
        val aesUtil = AESUtil()

        binding.encryptButton.setOnClickListener{
            aesUtil.keyFunction()
            val key = aesUtil.getKey()
            println("KEY: $key")
        }
         */
        /*
        val aes = AESUtil2()
        var encryptText = ""
        var decryptText = ""

        binding.encryptButton.setOnClickListener{
            try {
                val encrypt = aes.encrypt(binding.editTextText.text.toString())
                encryptText = String(encrypt, Charsets.UTF_8)
                binding.editTextText.setText(encryptText)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
        binding.decryptButton.setOnClickListener{
            try {
                val decrypt = aes.decrypt(encryptText.toByteArray(Charsets.UTF_8))
                println("DECRYPT: $decrypt")
                binding.editTextText.setText(decrypt)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
         */

        val aesUtil = AESUtil(this)
        val key = aesUtil.getKey()
        val editor = sharedPreferences.edit()
        val gson = Gson()
        val json = gson.toJson(key)
        //editor.putString("keyObject", json).apply()
        editor.putString("AES_KEY", Base64.encodeToString(key.encoded, Base64.DEFAULT))
        println("KEY: $key")
        val myKey = sharedPreferences.getString("AES_KEY",null)
        println("MY KEY: $myKey")
/*              WORKS
        val originalText = "Merhaba, dünya!"
        // Şifrele
        val encryptedText = aesUtil.encrypt(originalText)
        println("Şifrelenmiş Metin: $encryptedText")
        // Çöz
        val decryptedText = aesUtil.decrypt(encryptedText)
        println("Çözülmüş Metin: $decryptedText")
 */
/*              SORRY BRO
        val key = aesUtil.getKey()
        val encryptedData = aesUtil.encrypt("Data to encrypt")
        val decryptedData = aesUtil.decrypt(encryptedData)
        println("KEY: $key")
        var encryptedText = ""
        var decryptedText = ""
 */

        var encryptedText = ""
        var decryptedText = ""

        binding.encryptButton.setOnClickListener{
            encryptedText = aesUtil.encrypt(binding.editTextText.text.toString())
            binding.editTextText.setText(encryptedText)
        }

        binding.decryptButton.setOnClickListener{
            decryptedText = aesUtil.decrypt(encryptedText)
            binding.editTextText.setText(decryptedText)
        }
/*
        val aesUtil = AESUtil(context = applicationContext)
        val key = aesUtil.getKey()
        val editor = sharedPreferences.edit()

        val gson = Gson()
        val json = sharedPreferences.getString("MyObject", "")
        val obj: Key = gson.fromJson(json, Key::class.java)
        println("KEY: ${key.toString()}")
        println("obj: ${obj.toString()}")

        var myText = ""

        binding.encryptButton.setOnClickListener {
            val encryptedText = aesUtil.encrypt(binding.editTextText.text.toString())
            myText = encryptedText
            binding.editTextText.setText(encryptedText)
        }



        binding.decryptButton.setOnClickListener {
            binding.editTextText.setText(aesUtil.decrypt(myText))
        }

        */


        /*          FİLE İLE OLAN
        val cryptoManager = CryptoManager()


        var messageToEncrypt = ""
        var messageToDecrypt = ""

        binding.encryptButton.setOnClickListener {
            val bytes = messageToEncrypt.toByteArray()
            val file = File(filesDir, "secret.txt")

            if (!file.exists()) {
                file.createNewFile()
            }
            val fos = FileOutputStream(file)

            messageToDecrypt = cryptoManager.encrypt(
                bytes = bytes,
                outputStream = fos
            ).decodeToString()
            binding.editTextText.setText(messageToDecrypt)
        }

        binding.decryptButton.setOnClickListener {
            val file = File(filesDir, "secret.txt")
            messageToEncrypt = cryptoManager.decrypt(inputStream = FileInputStream(file)).decodeToString()
            println("AAAAAAA")
            //binding.editTextText.setText(messageToEncrypt)
            println("ENCRYPT EDİLEN MESAJ = $messageToEncrypt")
        }
    }

 */
    }


    /*          BU DA ONE WAY AGA
    fun hashPassword(password: String): String {
        val salt = BCrypt.gensalt()
        return BCrypt.hashpw(password, salt)
    }
    fun verifyPassword(inputPassword: String, hashedPassword: String): Boolean {
        return BCrypt.checkpw(inputPassword, hashedPassword)
    }
    val originalPassword = "SecretPassword"

        // Hash the password
        val hashedPassword = hashPassword(originalPassword)
        println("Hashed password: $hashedPassword")

        // Verify a password
        val inputPassword = "SecretPassword"
        val isPasswordCorrect = verifyPassword(inputPassword, hashedPassword)

        if (isPasswordCorrect) {
            println("Password is correct.")
        } else {
            println("Password is incorrect.")
        }
     */

    /*         ...GERİ DÖNÜŞÜ YOK SHA256'da   Encrypt var Decrypt yok...

    fun String.toSHA256(): String {
        val messageDigest = MessageDigest.getInstance("SHA-256")
        val bytes = messageDigest.digest(this.toByteArray())

        // Convert the byte array to a hexadecimal string
        val stringBuilder = StringBuilder()
        for (byte in bytes) {
            stringBuilder.append(String.format("%02x", byte))
        }

        return stringBuilder.toString()
    }
    //             encryptedText = binding.editTextText.text.toString().toSHA256()
     */
}