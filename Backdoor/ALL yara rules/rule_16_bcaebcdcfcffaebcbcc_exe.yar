rule bcaebcdcfcffaebcbcc_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "__vbaStrCopy"
        $s4 = "__vbaVarSetObj"
        $s5 = "__vbaStrVarMove"
        $s6 = "_adj_fdivr_m16i"
        $s7 = "Justiciary4"
        $s8 = "Udgiftsfrtes6"
        $s9 = "Afbestillings"
        $s10 = "OriginalFilename"
        $s11 = "Svumninge1"
        $s12 = "Ameninjur1"
        $s13 = "VS_VERSION_INFO"
        $s14 = "CompanyName"
        $s15 = "__vbaObjSet"
        $s16 = "landjordens"
        $s17 = "FileVersion"
        $s18 = "__vbaChkstk"
        $s19 = "Translation"
        $s20 = "tSn56iNbS\\"
condition:
    uint16(0) == 0x5a4d and filesize < 65KB and
    4 of them
}
    
