rule fdebbaceabcdffbfaadedfaf_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "positional parameters"
        $s6 = " exceeds the maximum of "
        $s7 = "CreateIoCompletionPort"
        $s8 = "t&1'1: 10t ;t-;!t  1: =;:uY^"
        $s9 = "executable format error"
        $s10 = "WNetAddConnection2A"
        $s11 = "result out of range"
        $s12 = "directory not empty"
        $s13 = "invalid string position"
        $s14 = "operation canceled"
        $s15 = "0123456789-"
        $s16 = "LC_MONETARY"
        $s17 = "english-jamaica"
        $s18 = "Eursni`'\"t')))"
        $s19 = "`local vftable'"
        $s20 = "6!7*7-829T<^<h<"
condition:
    uint16(0) == 0x5a4d and filesize < 926KB and
    4 of them
}
    
