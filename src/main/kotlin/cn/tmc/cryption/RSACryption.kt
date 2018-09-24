package cn.tmc.cryption

import com.tmc.cryption.Base64Cryption
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

object RSACryption {

    // 加密最大长度
    val ENCRYPT_MAX_SIZE=117
    //解密最大长度
    val DECRYPT_MAX_SIZE=128
    //保存公钥与私钥
    val publicKeyString="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDV9ninr47WlRjexpEgSAmpFv55Rc/B/4WTXtVZoq5xHtPl8oLog2x5uy4NzIlg+EYncyBQRxcJk0uRB0BSaruak3HPC68oX4dJ/RrbWajVYkT88BCe00InDOgvIZ5eWhqAfOam6sL9rurCqN05nkt8CYkY6PWqCVCMYySM8qv2aQIDAQAB"
    val privateKeyString="MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBANX2eKevjtaVGN7GkSBICakW/nlFz8H/hZNe1VmirnEe0+XyguiDbHm7Lg3MiWD4RidzIFBHFwmTS5EHQFJqu5qTcc8Lryhfh0n9GttZqNViRPzwEJ7TQicM6C8hnl5aGoB85qbqwv2u6sKo3TmeS3wJiRjo9aoJUIxjJIzyq/ZpAgMBAAECgYBRIsnWLMiprphjwkC+URL4v/N34XVLR65LmCanev1TgDEyfagOq+eysbxhFzLxRrSzuQCD8LFXvDdno6xMlJTW85Rp8CXJseF82qfbt1grnmm7AEnHTRVanwQG3fCZedFQtftiJTAV5z/ZF1/Aud5I+SybgGtIZoqBKN/NtrSuQQJBAO3j8gABvQkeXtq7F4j7208CfzpNQXfRN8AF1c/ISEiZomz8gRlmm73paF+1aUa9QGnxEn+jR50XTNd8GgfWGCUCQQDmQDg5YBoLrKEr954+0KEBxn5uTrh4hj2AZyvE4hUjEZc9Zx4wb8H+oDC4EVtOYJdEOnwz7x2idZLoUNKbsv/1AkALGo+qJmqfaVZ+GSuBDlhvOKudmguLPy29/ce8GhodoWYudh7Eg8CTPbjMdthCIAVIrKLzaDiogXTpvfYtFXYtAkAC1OtcGUh4uEjLJ6J0l1BDm1NWu/Uc1lnPSHWLWFR2N/MqOChw5A74uLOgr+X1ks6JckawxNISe2uxG71bWNo5AkBm+uEKwcHyeDogPVZqGy4VQhgTo3vbWMj0UsDWK/Q37SUcSIxyvZ3YunGGMA6yULmlbBmPOdlUtBKhdb7xDPwJIJjy5qyvMDLfJ1jqKZW3DVMnLuqsZ+tjooMOMjsnBENIxyV1GmRNCn5vZJI6KPeecScgTBW8wpliO7uLPdUuEMOCy0sn40Qc9ortXA+TCFIxHVLoWXVamaU7BHsn+gGSfJCcSRUvKXEUsbcsy55hKtTTZvxmnBi+fOUoqLan7ghoXBRCct0a5JAXAxVZzjaz0scxg7L9QoEFoLFB9nikyKo6SQ2rmN9pli72AUA86x4LpMQECeLFiOq3UTjNURiKJKRWBXaWtGN62CdrWSAi9NRoSzFGqt+degARnqiKBioXLZyd8jU/7o8FSsPlFGsxEePljIRyDoEQrpbX1cJpig=="

    //获取私钥
    fun getPrivateKey():PrivateKey{
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(PKCS8EncodedKeySpec(Base64Cryption.decode(privateKeyString)))
    }

    //获取公钥
    fun getPublicKey():PublicKey{
        val kf=KeyFactory.getInstance("RSA")
        return kf.generatePublic(X509EncodedKeySpec(Base64Cryption.decode(publicKeyString)))
    }

    fun privateEncryption(str:String,privateKey:PrivateKey):ByteArray{

        val byteArray=str.toByteArray()
        //缓存临时加密内容
        var temp:ByteArray?
        var offset=0
        //私钥加密，选择加密算法
        val cipher = Cipher.getInstance("RSA")
        val bos = ByteArrayOutputStream()
        cipher.init(Cipher.ENCRYPT_MODE,privateKey)
        while(byteArray.size-offset>0){
            if(byteArray.size-offset>=ENCRYPT_MAX_SIZE){
                temp=cipher.doFinal(byteArray,offset, ENCRYPT_MAX_SIZE)
                offset+= ENCRYPT_MAX_SIZE
            }else{
                temp=cipher.doFinal(byteArray,offset,byteArray.size-offset)
                offset=byteArray.size
            }
            bos.write(temp)
        }
        bos.close()
        return bos.toByteArray()
    }

    fun publicEncryption(str:String,publicKey:PublicKey):ByteArray{
        //公钥加密，选择加密算法
        val byteArray=str.toByteArray()
        //缓存临时加密内容
        var temp:ByteArray?
        var offset=0
        //私钥加密，选择加密算法
        val cipher = Cipher.getInstance("RSA")
        val bos = ByteArrayOutputStream()
        cipher.init(Cipher.ENCRYPT_MODE,publicKey)
        while(byteArray.size-offset>0){
            if(byteArray.size-offset>=ENCRYPT_MAX_SIZE){
                temp=cipher.doFinal(byteArray,offset, ENCRYPT_MAX_SIZE)
                offset+= ENCRYPT_MAX_SIZE
            }else{
                temp=cipher.doFinal(byteArray,offset,byteArray.size-offset)
                offset=byteArray.size
            }
            bos.write(temp)
        }
        bos.close()
        return bos.toByteArray()
    }

    fun privateDecryption(str:ByteArray,privateKey:PrivateKey):ByteArray{

        //缓存临时加密内容
        var temp:ByteArray?
        var offset=0
        //私钥加密，选择加密算法
        val cipher = Cipher.getInstance("RSA")
        val bos = ByteArrayOutputStream()
        cipher.init(Cipher.DECRYPT_MODE,privateKey)
        while(str.size-offset>0){
            if(str.size-offset>=DECRYPT_MAX_SIZE){
                temp=cipher.doFinal(str,offset, DECRYPT_MAX_SIZE)
                offset+= DECRYPT_MAX_SIZE
            }else{
                temp=cipher.doFinal(str,offset,str.size-offset)
                offset=str.size
            }
            bos.write(temp)
        }
        bos.close()
        return bos.toByteArray()
    }

    fun publicDecryption(str:ByteArray,publicKey:PublicKey):ByteArray{

        //缓存临时加密内容
        var temp:ByteArray?
        var offset=0
        //私钥加密，选择加密算法
        val cipher = Cipher.getInstance("RSA")
        val bos = ByteArrayOutputStream()
        cipher.init(Cipher.DECRYPT_MODE,publicKey)
        while(str.size-offset>0){
            if(str.size-offset>=DECRYPT_MAX_SIZE){
                temp=cipher.doFinal(str,offset, DECRYPT_MAX_SIZE)
                offset+= DECRYPT_MAX_SIZE
            }else{
                temp=cipher.doFinal(str,offset,str.size-offset)
                offset=str.size
            }
            bos.write(temp)
        }
        bos.close()
        return bos.toByteArray()
    }
}