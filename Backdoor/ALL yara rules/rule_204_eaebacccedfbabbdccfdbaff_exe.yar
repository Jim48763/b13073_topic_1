rule eaebacccedfbabbdccfdbaff_exe {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "7 7$7(7,7074787<7@7D7H7L7P7\\=d=l=t=|="
        $s5 = "executable format error"
        $s6 = "result out of range"
        $s7 = "directory not empty"
        $s8 = "invalid string position"
        $s9 = "ios_base::failbit set"
        $s10 = "invalid distance code"
        $s11 = "operation canceled"
        $s12 = "LC_MONETARY"
        $s13 = "HowZ)WI3/2j"
        $s14 = "k$w#Q~Pfzy:"
        $s15 = ";K(7d:tqxQ_"
        $s16 = "`local vftable'"
        $s17 = "english-jamaica"
        $s18 = "spanish-venezuela"
        $s19 = "GetModuleHandleW"
        $s20 = "RemoveDirectoryA"
condition:
    uint16(0) == 0x5a4d and filesize < 3038KB and
    4 of them
}
    
