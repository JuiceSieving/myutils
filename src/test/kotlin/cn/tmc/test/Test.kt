package cn.tmc.test

import cn.tmc.cryption.AESCryption
import cn.tmc.cryption.CaesarCryption
import cn.tmc.cryption.DESCryption
import cn.tmc.cryption.RSACryption
import com.tmc.cryption.Base64Cryption
import sun.misc.BASE64Encoder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

fun main(args: Array<String>) {
    var str="hello world"
    var censtr=CaesarCryption.encryption(str,5)
    var cdestr=CaesarCryption.decryption(censtr,5)
    println(censtr)
    println(cdestr)

    var denstr=DESCryption.encryption(str,"12345678")
    var ddestr=DESCryption.decryption(denstr,"12345678")
    println(String(denstr))
    println(String(ddestr))

    var benstr=Base64Cryption.encode(str.toByteArray())
    var bdestr=Base64Cryption.decode(benstr)
    println(benstr)
    println(String(bdestr))

    var aenstr=AESCryption.encryption(str,"1234567812345678")
    var adestr=AESCryption.decryption(aenstr,"1234567812345678")
    println(aenstr)
    println(String(adestr))

    //生成密钥对
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    val genKeyPair = keyPairGenerator.genKeyPair()
    //生成公钥
    val publicKey = genKeyPair.public
    //生成私钥
    val privateKey = genKeyPair.private
    println("g=>"+Base64Cryption.encode(publicKey.encoded))
    println("s=>"+Base64Cryption.encode(privateKey.encoded))

    /*val encrypt = RSACryption.publicEncryption("中华人民共和国中华人民共和国中华人民共和国中华人民共和国中华人民共和国中华人民共和国", publicKey)
    println(Base64Cryption.encode(encrypt))
    val decrypt=RSACryption.privateDecryption(encrypt,privateKey)
    println(String(decrypt))*/

    //保存密钥对
    val publicKeyString="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDV9ninr47WlRjexpEgSAmpFv55Rc/B/4WTXtVZoq5xHtPl8oLog2x5uy4NzIlg+EYncyBQRxcJk0uRB0BSaruak3HPC68oX4dJ/RrbWajVYkT88BCe00InDOgvIZ5eWhqAfOam6sL9rurCqN05nkt8CYkY6PWqCVCMYySM8qv2aQIDAQAB"
    val privateKeyString="MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBANX2eKevjtaVGN7GkSBICakW/nlFz8H/hZNe1VmirnEe0+XyguiDbHm7Lg3MiWD4RidzIFBHFwmTS5EHQFJqu5qTcc8Lryhfh0n9GttZqNViRPzwEJ7TQicM6C8hnl5aGoB85qbqwv2u6sKo3TmeS3wJiRjo9aoJUIxjJIzyq/ZpAgMBAAECgYBRIsnWLMiprphjwkC+URL4v/N34XVLR65LmCanev1TgDEyfagOq+eysbxhFzLxRrSzuQCD8LFXvDdno6xMlJTW85Rp8CXJseF82qfbt1grnmm7AEnHTRVanwQG3fCZedFQtftiJTAV5z/ZF1/Aud5I+SybgGtIZoqBKN/NtrSuQQJBAO3j8gABvQkeXtq7F4j7208CfzpNQXfRN8AF1c/ISEiZomz8gRlmm73paF+1aUa9QGnxEn+jR50XTNd8GgfWGCUCQQDmQDg5YBoLrKEr954+0KEBxn5uTrh4hj2AZyvE4hUjEZc9Zx4wb8H+oDC4EVtOYJdEOnwz7x2idZLoUNKbsv/1AkALGo+qJmqfaVZ+GSuBDlhvOKudmguLPy29/ce8GhodoWYudh7Eg8CTPbjMdthCIAVIrKLzaDiogXTpvfYtFXYtAkAC1OtcGUh4uEjLJ6J0l1BDm1NWu/Uc1lnPSHWLWFR2N/MqOChw5A74uLOgr+X1ks6JckawxNISe2uxG71bWNo5AkBm+uEKwcHyeDogPVZqGy4VQhgTo3vbWMj0UsDWK/Q37SUcSIxyvZ3YunGGMA6yULmlbBmPOdlUtBKhdb7xDPwJ\n" +
            "IJjy5qyvMDLfJ1jqKZW3DVMnLuqsZ+tjooMOMjsnBENIxyV1GmRNCn5vZJI6KPeecScgTBW8wpliO7uLPdUuEMOCy0sn40Qc9ortXA+TCFIxHVLoWXVamaU7BHsn+gGSfJCcSRUvKXEUsbcsy55hKtTTZvxmnBi+fOUoqLan7ghoXBRCct0a5JAXAxVZzjaz0scxg7L9QoEFoLFB9nikyKo6SQ2rmN9pli72AUA86x4LpMQECeLFiOq3UTjNURiKJKRWBXaWtGN62CdrWSAi9NRoSzFGqt+degARnqiKBioXLZyd8jU/7o8FSsPlFGsxEePljIRyDoEQrpbX1cJpig=="
    val kf = KeyFactory.getInstance("RSA")
    val generatePrivate = kf.generatePrivate(PKCS8EncodedKeySpec(Base64Cryption.decode(privateKeyString)))
    val generatePublic = kf.generatePublic(X509EncodedKeySpec(Base64Cryption.decode(publicKeyString)))
    val encrypt = RSACryption.publicEncryption("中华人民共和国中华人民共和国中华人民共和国中华人民共和国中华人民共和国中华人民共和国", generatePublic)
    println(Base64Cryption.encode(encrypt))
    val decrypt=RSACryption.privateDecryption(encrypt,generatePrivate)
    println(String(decrypt))
}