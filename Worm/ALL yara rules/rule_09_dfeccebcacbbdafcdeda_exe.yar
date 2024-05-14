rule dfeccebcacbbdafcdeda_exe {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "`vector destructor iterator'"
        $s5 = " exceeds the maximum of "
        $s6 = ": message length of "
        $s7 = "executable format error"
        $s8 = "directory not empty"
        $s9 = "result out of range"
        $s10 = "RegSetValueExA"
        $s11 = "   Q: What to tell my boss?"
        $s12 = "invalid string position"
        $s13 = "operation canceled"
        $s14 = "ThisObject:"
        $s15 = "LC_MONETARY"
        $s16 = "Hi Company,"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "GetKeyboardType"
        $s20 = "GetThreadLocale"
condition:
    uint16(0) == 0x5a4d and filesize < 546KB and
    4 of them
}
    
