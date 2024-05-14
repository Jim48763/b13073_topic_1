rule bebfccbfbbeddececefc_exe {
strings:
        $s1 = "R~\\IZ__RdZ]W\\Dp_Rp\\]@\\_VdZ]W\\Dp_RAVC\\@V"
        $s2 = "GetKeyboardLayout"
        $s3 = "english-caribbean"
        $s4 = "spanish-guatemala"
        $s5 = "cross device link"
        $s6 = "bad function call"
        $s7 = "CreateThreadpoolTimer"
        $s8 = "`vector destructor iterator'"
        $s9 = "executable format error"
        $s10 = "result out of range"
        $s11 = "directory not empty"
        $s12 = "invalid string position"
        $s13 = "ios_base::failbit set"
        $s14 = "operation canceled"
        $s15 = "LC_MONETARY"
        $s16 = "IsWindowVisible"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "spanish-venezuela"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 468KB and
    4 of them
}
    
