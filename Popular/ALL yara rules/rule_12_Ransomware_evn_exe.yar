rule Ransomware_evn_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "\\AppData\\Local\\bcd1.bat"
        $s6 = "executable format error"
        $s7 = "result out of range"
        $s8 = "directory not empty"
        $s9 = "invalid string position"
        $s10 = "operation canceled"
        $s11 = "LC_MONETARY"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "spanish-venezuela"
        $s15 = "TerminateProcess"
        $s16 = "SetFilePointerEx"
        $s17 = "DispatchMessageW"
        $s18 = "destination address required"
        $s19 = "connection refused"
        $s20 = "EventWriteTransfer"
condition:
    uint16(0) == 0x5a4d and filesize < 320KB and
    4 of them
}
    
