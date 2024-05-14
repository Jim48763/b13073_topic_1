rule edeedfdcfcdfbbecebaceddaf_exe {
strings:
        $s1 = "'%s' is not a valid date"
        $s2 = "ECompressInternalError"
        $s3 = "http://ocsp.comodoca.com0"
        $s4 = "EnglishName"
        $s5 = "I/@]N?mS1E*"
        $s6 = "P+e#jXB(|=y"
        $s7 = "xNJ5kcC*2/)"
        $s8 = "m\"=JIA`~^;"
        $s9 = "S^\"p,q5W9N"
        $s10 = "t_WH'+Pks[r"
        $s11 = "=q>hy0dA849"
        $s12 = "ZkV]s*MUL<A"
        $s13 = "LoadStringA"
        $s14 = "4^'VO@C(Wgk"
        $s15 = "s[Q7&J_<-bR"
        $s16 = ":m=\",]ovl7"
        $s17 = "*q:h\"M(OfH"
        $s18 = "|N&4d,A{>9a"
        $s19 = "y2/#SdGJ-<D"
        $s20 = "fI9k*v(d`]G"
condition:
    uint16(0) == 0x5a4d and filesize < 4915KB and
    4 of them
}
    
