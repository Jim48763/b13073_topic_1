rule eebcbeafcbcecbbcbeaebfaacaadc_exe {
strings:
        $s1 = "Pn&+W91-U4>"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "__vbaLenBstr"
        $s5 = "__vbaVarTstEq"
        $s6 = "Disc Soft Ltd"
        $s7 = "LegalTrademarks"
        $s8 = "[1Y}kOE(q "
        $s9 = "D5F1)w@:ju"
        $s10 = "Berezovsky7"
        $s11 = "Emparadise8"
        $s12 = "DllFunctionCall"
        $s13 = "OriginalFilename"
        $s14 = "@Aa>he>Y7F"
        $s15 = "Crosshead1"
        $s16 = "|Nm#:Mdbj|"
        $s17 = "%Hs&C9;brC"
        $s18 = "Dayworker2"
        $s19 = "VS_VERSION_INFO"
        $s20 = "CompanyName"
condition:
    uint16(0) == 0x5a4d and filesize < 405KB and
    4 of them
}
    
