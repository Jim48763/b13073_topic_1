rule dacebfafaafdeaacbccbcebcdea_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "`vector destructor iterator'"
        $s4 = "invalid string position"
        $s5 = "ios_base::failbit set"
        $s6 = "GetConsoleOutputCP"
        $s7 = "6\"bh>nB*~N"
        $s8 = "LC_MONETARY"
        $s9 = "PrintDlgExW"
        $s10 = "english-jamaica"
        $s11 = "mixerGetNumDevs"
        $s12 = "`local vftable'"
        $s13 = "SetupFindNextLine"
        $s14 = "spanish-venezuela"
        $s15 = "TerminateProcess"
        $s16 = "GetModuleHandleW"
        $s17 = "EnterCriticalSection"
        $s18 = "=sDrZrcFEK*X"
        $s19 = "south-africa"
        $s20 = "COMDLG32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 416KB and
    4 of them
}
    
