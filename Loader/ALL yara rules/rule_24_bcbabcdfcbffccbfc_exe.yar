rule bcbabcdfcbffccbfc_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "Fremskridtsbyens"
        $s4 = "Slagskibene4"
        $s5 = "__vbaStrCopy"
        $s6 = "__vbaVarTstEq"
        $s7 = "blikkenslagermesters"
        $s8 = "_adj_fdivr_m32"
        $s9 = "Retranscri.exe"
        $s10 = "LegalTrademarks"
        $s11 = "Coeldershi1"
        $s12 = "AstroPicker"
        $s13 = "EFTERFORSKNINGSCENTER"
        $s14 = "Buphthalmia8"
        $s15 = "Redningsbltes"
        $s16 = "Distraktionens"
        $s17 = "OriginalFilename"
        $s18 = "NORDAMERIKANERS"
        $s19 = "Artificious4"
        $s20 = "Decompressive"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    
