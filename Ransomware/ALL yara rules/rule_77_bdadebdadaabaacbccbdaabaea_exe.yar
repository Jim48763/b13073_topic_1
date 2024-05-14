rule bdadebdadaabaacbccbdaabaea_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = " exceeds the maximum of "
        $s6 = ": message length of "
        $s7 = "executable format error"
        $s8 = "result out of range"
        $s9 = "directory not empty"
        $s10 = "RegSetValueExA"
        $s11 = "   Q: What to tell my boss?"
        $s12 = "invalid string position"
        $s13 = "operation canceled"
        $s14 = "Hi Company,"
        $s15 = "LC_MONETARY"
        $s16 = "ThisObject:"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "spanish-venezuela"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 504KB and
    4 of them
}
    
