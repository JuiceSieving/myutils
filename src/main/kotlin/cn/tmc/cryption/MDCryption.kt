package cn.tmc.cryption

import java.security.MessageDigest

object MDCryption {

    fun md5Encryption(str:String):String{
        //选择md5加密方式,加密后长度为16字节,加密后转成16进制是32字节
        val digest = MessageDigest.getInstance("MD5")
        val result = digest.digest(str.toByteArray())
        //将加密结果的每个位变为16进制
        return toHexString(result)
    }

    fun sha1Encryption(str:String):String{
        //选择sha1加密方式,加密后长度为16字节,加密后转成16进制是32字节
        val digest = MessageDigest.getInstance("SHA-1")
        val result = digest.digest(str.toByteArray())
        //将加密结果的每个位变为16进制
        return toHexString(result)
    }

    fun sha256Encryption(str:String):String{
        //选择sha256加密方式,加密后长度为16字节,加密后转成16进制是32字节
        val digest = MessageDigest.getInstance("SHA-256")
        val result = digest.digest(str.toByteArray())
        //将加密结果的每个位变为16进制
        return toHexString(result)
    }

    fun toHexString(byteArray: ByteArray):String{
        //将加密后的结果转成16进制
        return with(StringBuilder()){
            byteArray.forEach {
                val hex = it.toInt() and 0xff
                val hexStr=Integer.toHexString(hex)
                //变成十六进制后若不足2位则前面加0
                if(hexStr.length<2){
                    append("0").append(hexStr)
                }else{
                    append(hexStr)
                }
            }
            toString()
        }
    }

}