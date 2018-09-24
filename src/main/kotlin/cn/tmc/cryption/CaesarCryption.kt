package cn.tmc.cryption

object CaesarCryption{
    fun encryption(str:String,key:Int):String{
        return with(StringBuilder()){
            var charArray = str.toCharArray()
            charArray.forEach {
                var ascii=it.toInt()
                ascii+=key
                append(ascii.toChar())
            }
            toString()
        }
    }

    fun decryption(str:String,key:Int):String{
        return with(StringBuilder()){
            var charArray = str.toCharArray()
            charArray.forEach {
                var ascii=it.toInt()
                ascii-=key
                append(ascii.toChar())
            }
            toString()
        }
    }
}