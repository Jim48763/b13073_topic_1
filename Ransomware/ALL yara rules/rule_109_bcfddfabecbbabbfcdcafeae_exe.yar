rule bcfddfabecbbabbfcdcafeae_exe {
strings:
        $s1 = "cross device link"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "AT@3=F/@T03FF1KI@KTH@("
        $s4 = "executable format error"
        $s5 = "@3<<88I:9@TP@NO3I7N"
        $s6 = "result out of range"
        $s7 = "directory not empty"
        $s8 = "SNABTPJSF9M75TBTFJ7"
        $s9 = "invalid string position"
        $s10 = "operation canceled"
        $s11 = "GD;.lfk5Xnb"
        $s12 = "]B!I0P7'~$u"
        $s13 = "`local vftable'"
        $s14 = "TerminateProcess"
        $s15 = "SetFilePointerEx"
        $s16 = "SetThreadStackGuarantee"
        $s17 = "@3FI@;;:M1@A@KF/5@SKFI"
        $s18 = "destination address required"
        $s19 = "IFKB8IP<<@I<I7PS<745'"
        $s20 = "connection refused"
condition:
    uint16(0) == 0x5a4d and filesize < 756KB and
    4 of them
}
    
