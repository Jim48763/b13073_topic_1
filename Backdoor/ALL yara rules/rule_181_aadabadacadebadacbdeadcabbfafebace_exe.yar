rule aadabadacadebadacbdeadcabbfafebace_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "H]ajbT\"0y}"
        $s5 = "c,]h\"rP7lF"
        $s6 = "ayRuP2\"be|"
        $s7 = "ProductName"
        $s8 = "nQ=S l&\"-u"
        $s9 = "!\">@NXfMxj"
        $s10 = "Qpo|g\"=O0."
        $s11 = "VarFileInfo"
        $s12 = "*+TPe\"ft$j"
        $s13 = "S4@[9ix1>wV"
        $s14 = "URFXQt8jur "
        $s15 = "fI`=Z0*an';"
        $s16 = "=Q@%+m?.*fE"
        $s17 = "FileDescription"
        $s18 = "DialogBoxParamA"
        $s19 = "GetShortPathNameA"
        $s20 = "RemoveDirectoryA"
condition:
    uint16(0) == 0x5a4d and filesize < 3325KB and
    4 of them
}
    
