rule ccaeffeffecffffebeabfcaeeab_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "`vector destructor iterator'"
        $s3 = "BcImages.MainImages"
        $s4 = "CoInitializeEx"
        $s5 = "Runtime Error!"
        $s6 = "ProductName"
        $s7 = "\"t'SJ~5]?$"
        $s8 = "~(P.}\"iQC8"
        $s9 = "LC_MONETARY"
        $s10 = "bl,]03\"~M5"
        $s11 = "VarFileInfo"
        $s12 = "DialogBoxParamA"
        $s13 = "QueryDosDeviceA"
        $s14 = "english-jamaica"
        $s15 = "`local vftable'"
        $s16 = "FileDescription"
        $s17 = "spanish-venezuela"
        $s18 = "Nie zainstalowano"
        $s19 = "chinese-singapore"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 323KB and
    4 of them
}
    
