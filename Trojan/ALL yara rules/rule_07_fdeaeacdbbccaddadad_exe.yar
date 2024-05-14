rule fdeaeacdbbccaddadad_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "_T.aVmd8k*;"
        $s4 = "__vbaStrCopy"
        $s5 = "__vbaVarTstNe"
        $s6 = "_adj_fdivr_m64"
        $s7 = "FJUMREHOVEDERS"
        $s8 = "&!% !#>\"4)"
        $s9 = "ldYrZZIm7220"
        $s10 = "ugpax\"#?u}}"
        $s11 = "__vbaLateMemSt"
        $s12 = "OriginalFilename"
        $s13 = "4#73#52#\"f2."
        $s14 = "__vbaI4Str"
        $s15 = "Moderliges"
        $s16 = "legetjsfor"
        $s17 = "Earableosc"
        $s18 = "VS_VERSION_INFO"
        $s19 = "BorderStyle"
        $s20 = "CompanyName"
condition:
    uint16(0) == 0x5a4d and filesize < 161KB and
    4 of them
}
    
