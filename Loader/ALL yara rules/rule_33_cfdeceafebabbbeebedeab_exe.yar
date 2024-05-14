rule cfdeceafebabbbeebedeab_exe {
strings:
        $s1 = "&9C:\\Users\\Hidd\"ask\\"
        $s2 = "t3_51<Et:<et6<;tFD"
        $s3 = "KZ6B4$\"lok"
        $s4 = "AsDoubleT\""
        $s5 = "CustomizerU"
        $s6 = "o!<^%~m6Wbg"
        $s7 = "wCheckbox&R"
        $s8 = "TClipboardg"
        $s9 = "Am#lf\">,7D"
        $s10 = "SystemInfo>"
        $s11 = "4!YM.1wUx*X"
        $s12 = "7<CIPenDash"
        $s13 = "VarFileInfo"
        $s14 = "\"Q[NdR^JL5"
        $s15 = "7hlU+Rux3=;"
        $s16 = "ProductName"
        $s17 = "iUd 8M{;RDg"
        $s18 = "AutoSize\"y"
        $s19 = "<IMG src=\""
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 1226KB and
    4 of them
}
    
