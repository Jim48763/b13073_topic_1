rule ecdfcddadeafbcecaaadbeeccfa_exe {
strings:
        $s1 = "bad function call"
        $s2 = "cross device link"
        $s3 = "english-caribbean"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = " exceeds the maximum of "
        $s7 = "executable format error"
        $s8 = "directory not empty"
        $s9 = "result out of range"
        $s10 = "invalid string position"
        $s11 = "operation canceled"
        $s12 = "GetConsoleOutputCP"
        $s13 = "LC_MONETARY"
        $s14 = "english-jamaica"
        $s15 = "`local vftable'"
        $s16 = "IsWindowVisible"
        $s17 = "cpp-httplib/0.9"
        $s18 = "spanish-venezuela"
        $s19 = "chinese-singapore"
        $s20 = "SetFilePointerEx"
condition:
    uint16(0) == 0x5a4d and filesize < 714KB and
    4 of them
}
    
