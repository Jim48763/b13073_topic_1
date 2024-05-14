rule fcebefcaedebfefadfdddefddcfe_exe {
strings:
        $s1 = "SAMP\\servers.fav"
        $s2 = "cross device link"
        $s3 = "english-caribbean"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = "30:8:@:T:8;@;D;H;L;P;T;X;\\;`;d;h;l;p;t;x;"
        $s7 = "CreateIoCompletionPort"
        $s8 = "Software\\Valve\\Steam"
        $s9 = "executable format error"
        $s10 = "directory not empty"
        $s11 = "result out of range"
        $s12 = "invalid string position"
        $s13 = "\\Exodus\\exodus.wallet\\"
        $s14 = "On tree page %d cell %d: "
        $s15 = "operation canceled"
        $s16 = "LC_MONETARY"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "| System ver: ?"
        $s20 = "spanish-venezuela"
condition:
    uint16(0) == 0x5a4d and filesize < 908KB and
    4 of them
}
    
