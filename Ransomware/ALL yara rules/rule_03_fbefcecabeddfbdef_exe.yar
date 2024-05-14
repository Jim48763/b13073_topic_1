rule fbefcecabeddfbdef_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "executable format error"
        $s6 = "WNetAddConnection2A"
        $s7 = "result out of range"
        $s8 = "directory not empty"
        $s9 = "invalid string position"
        $s10 = "operation canceled"
        $s11 = ".?AVbad_cast@std@@"
        $s12 = "0123456789-"
        $s13 = "LC_MONETARY"
        $s14 = "english-jamaica"
        $s15 = "`local vftable'"
        $s16 = "Q~{w|f2@AS2ywk2"
        $s17 = "spanish-venezuela"
        $s18 = "TerminateProcess"
        $s19 = "SetFilePointerEx"
        $s20 = "ContextStackSize"
condition:
    uint16(0) == 0x5a4d and filesize < 407KB and
    4 of them
}
    
