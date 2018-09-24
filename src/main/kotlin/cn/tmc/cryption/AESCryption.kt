package cn.tmc.cryption

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object AESCryption {

    fun encryption(str:String ,key:String):ByteArray{
        //指定加密算法
        val cipher = Cipher.getInstance("AES")
        val secretKeySpec = SecretKeySpec(key.toByteArray(), "AES")
        cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec)
        return cipher.doFinal(str.toByteArray())
    }

    fun decryption(str:ByteArray,key:String):ByteArray{
        //指定加密算法
        val cipher = Cipher.getInstance("AES")
        val secretKeySpec = SecretKeySpec(key.toByteArray(), "AES")
        cipher.init(Cipher.DECRYPT_MODE,secretKeySpec)
        return cipher.doFinal(str)
    }
}