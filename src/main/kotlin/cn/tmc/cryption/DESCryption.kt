package cn.tmc.cryption

import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec

object DESCryption {
    fun encryption(str:String,key:String):ByteArray{
        val cipher = Cipher.getInstance("DES")
        val skf = SecretKeyFactory.getInstance("DES")
        val desKeySpec = DESKeySpec(key.toByteArray())
        val generateSecret = skf.generateSecret(desKeySpec)
        cipher.init(Cipher.ENCRYPT_MODE,generateSecret)
        //加密
        return cipher.doFinal(str.toByteArray())
    }

    fun decryption(str:ByteArray,key:String):ByteArray{
        val cipher = Cipher.getInstance("DES")
        val skf = SecretKeyFactory.getInstance("DES")
        val desKeySpec = DESKeySpec(key.toByteArray())
        val generateSecret = skf.generateSecret(desKeySpec)
        cipher.init(Cipher.DECRYPT_MODE,generateSecret)
        //加密
        return cipher.doFinal(str)
    }
}