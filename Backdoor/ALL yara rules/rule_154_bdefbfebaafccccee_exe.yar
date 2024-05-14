rule bdefbfebaafccccee_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "cross device link"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = "x-ebcdic-koreanandkoreanextended"
        $s7 = "executable format error"
        $s8 = "result out of range"
        $s9 = "If-Unmodified-Since"
        $s10 = "directory not empty"
        $s11 = "x-ebcdic-icelandic-euro"
        $s12 = "h([0-9a-fA-F])"
        $s13 = "invalid string position"
        $s14 = "ios_base::failbit set"
        $s15 = "operation canceled"
        $s16 = ".?AVbad_cast@std@@"
        $s17 = "LC_MONETARY"
        $s18 = "Accept-Encoding"
        $s19 = "english-jamaica"
        $s20 = "`local vftable'"
condition:
    uint16(0) == 0x5a4d and filesize < 557KB and
    4 of them
}
    
