rule ddbadcdbdcefbedfdedfabdf_exe {
strings:
        $s1 = "Sobrescribir archivo?"
        $s2 = "elite prepisati datoteko?"
        $s3 = "Een ogenblik geduld"
        $s4 = "invalid distance code"
        $s5 = "f#sax3o9kFh"
        $s6 = "W|?:*9-qtBD"
        $s7 = "w@Hc>!i#3Jf"
        $s8 = "h!FLx:1}wVs"
        $s9 = "\"370=n]yEm"
        $s10 = "a*IZf\"[4%c"
        $s11 = "+Q<\"A7@2-g"
        $s12 = "^ZG}~!(6yqK"
        $s13 = "<3TZ+G*UO_="
        $s14 = "2\"eyH!nQFB"
        $s15 = "{GdOyI|i%uK"
        $s16 = "A&{9d=p%i\""
        $s17 = "M\"EyeTj#-_"
        $s18 = "LoadStringA"
        $s19 = "GetKeyboardType"
        $s20 = "   </trustInfo>"
condition:
    uint16(0) == 0x5a4d and filesize < 2561KB and
    4 of them
}
    
