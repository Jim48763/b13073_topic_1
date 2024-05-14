rule dbcddfbbcbbcbeccebaaa_exe {
strings:
        $s1 = "Forhandlingsforsg"
        $s2 = "VarFileInfo"
        $s3 = ",.igj|-Vvaf"
        $s4 = "ProductName"
        $s5 = "F=Rja<C8~,J"
        $s6 = "__vbaStrCopy"
        $s7 = "PRAKTIKPLADSERNES"
        $s8 = "axisymmetrically"
        $s9 = "Glauconitization2"
        $s10 = "missyllabication"
        $s11 = "_adj_fdivr_m32"
        $s12 = "Sygehusvsenet2"
        $s13 = "Noncontinuably"
        $s14 = "LegalTrademarks"
        $s15 = "Francoise9"
        $s16 = "Ringmaker8"
        $s17 = "VsoHg&Tjt$"
        $s18 = "PSEUDOVELAR"
        $s19 = "__vbaUI1Str"
        $s20 = "nonsimulate"
condition:
    uint16(0) == 0x5a4d and filesize < 93KB and
    4 of them
}
    
