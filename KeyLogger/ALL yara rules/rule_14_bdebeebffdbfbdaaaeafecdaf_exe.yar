rule bdebeebffdbfbdaaaeafecdaf_exe {
strings:
        $s1 = "Enter your choice"
        $s2 = "cross device link"
        $s3 = "GetColorProfileElement"
        $s4 = "executable format error"
        $s5 = "result out of range"
        $s6 = "directory not empty"
        $s7 = "invalid string position"
        $s8 = "FINE DAY FOR FRIENDS."
        $s9 = "operation canceled"
        $s10 = "LIES TODAY."
        $s11 = "LC_MONETARY"
        $s12 = "`local vftable'"
        $s13 = "YOU NEED SOME FUN IN LIFE."
        $s14 = "spanish-venezuela"
        $s15 = "CreateJobObjectA"
        $s16 = "SetFilePointerEx"
        $s17 = "TerminateProcess"
        $s18 = "waveOutGetVolume"
        $s19 = "GetModuleHandleW"
        $s20 = "destination address required"
condition:
    uint16(0) == 0x5a4d and filesize < 1033KB and
    4 of them
}
    
