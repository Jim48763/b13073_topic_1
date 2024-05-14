rule fdeaeacddbedeeceafdacfbaa_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "mKIUHKJGGMM?;*%HJ"
        $s4 = "english-caribbean"
        $s5 = "GetEnvironmentStrings"
        $s6 = "RegSetValueExA"
        $s7 = "invalid string position"
        $s8 = "accDoDefaultAction"
        $s9 = "GetConsoleOutputCP"
        $s10 = "-),.(UMB@GH"
        $s11 = "LC_MONETARY"
        $s12 = "e[a(L8#x>$S"
        $s13 = ">5r/mCOwR.&"
        $s14 = "english-jamaica"
        $s15 = "`local vftable'"
        $s16 = "IsWindowVisible"
        $s17 = "6)MJOQO&M@EOGFU"
        $s18 = "UHOTKUD'%NORGHNOm"
        $s19 = "spanish-venezuela"
        $s20 = "GetModuleHandleA"
condition:
    uint16(0) == 0x5a4d and filesize < 439KB and
    4 of them
}
    
