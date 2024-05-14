rule eaeabdccddadbefccbcdcfbeb_exe {
strings:
        $s1 = "invalid distance code"
        $s2 = "lk}\"Wg[JVa"
        $s3 = "Mq$eJwS:o^%"
        $s4 = "cT[yM$-S/,u"
        $s5 = "r}91O`j|'4!"
        $s6 = "ebf@~h8\"FP"
        $s7 = "A$-3j'L#x+U"
        $s8 = "U&/3Lus,.=*"
        $s9 = "(pkqx!C[jG3"
        $s10 = "}lszPC^DIcg"
        $s11 = "F(y0k\"}ztC"
        $s12 = "VarFileInfo"
        $s13 = "ProductName"
        $s14 = "ZbG(i'A]S\""
        $s15 = "CkYVh?DE]cj"
        $s16 = "\"@8pHnUCPR"
        $s17 = ">!JV~m:/\"Y"
        $s18 = "jC@`<_MDT|8"
        $s19 = "IsWindowVisible"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 4614KB and
    4 of them
}
    
