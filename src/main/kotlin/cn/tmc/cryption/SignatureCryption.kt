package cn.tmc.cryption

import com.tmc.cryption.Base64Cryption
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

object SignatureCryption {

    //签名
    fun sign(str:String,privateKey: PrivateKey):String{
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(str.toByteArray())
        //签名
        val sign = signature.sign()
        return Base64Cryption.encode(sign)
    }

    //校验
    fun verify(str:String,publicKey: PublicKey,sign:String):Boolean{
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)
        signature.update(str.toByteArray())
        return signature.verify(Base64Cryption.decode(sign))
    }

}