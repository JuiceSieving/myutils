package cn.tmc.test

import cn.tmc.cryption.MDCryption
import cn.tmc.cryption.RSACryption
import cn.tmc.cryption.SignatureCryption
import com.tmc.cryption.Base64Cryption
import java.security.Signature

fun main(args: Array<String>) {
    val encryption = MDCryption.md5Encryption("Nice to see you")
    println(encryption)
    println(encryption.length)

    val sha1 = MDCryption.sha1Encryption("Nice to see you")
    println(sha1)
    println(sha1.length)

    val sha256 = MDCryption.sha256Encryption("Nice to see you")
    println(sha256)
    println(sha256.length)

    val str="hello world"
    val privateKey = RSACryption.getPrivateKey()
    val publicKey = RSACryption.getPublicKey()
    val sign = SignatureCryption.sign(str, privateKey)
    val flag = SignatureCryption.verify(str, publicKey, sign)
    println(flag)
}