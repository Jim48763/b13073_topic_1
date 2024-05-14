rule bbccdcffedebbcabcceeabbddb_dll {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "bad function call"
        $s4 = "Runtime Error!"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "Sgt3>_-=can"
        $s7 = "0~be=863_tD"
        $s8 = "~-.3\"o7a i"
        $s9 = "dD-<e .3bS9"
        $s10 = "n8\"opu46e "
        $s11 = "6f9o.u 4s\""
        $s12 = "536_ e\"d10"
        $s13 = "LC_MONETARY"
        $s14 = "pas<r\"In2v"
        $s15 = "1iWU4aQ~-f$"
        $s16 = "6/er 53CPSW"
        $s17 = "VarFileInfo"
        $s18 = "AenLU TptH@"
        $s19 = "8CM6.sb-1 3"
        $s20 = "tnkmr\"s53l"
condition:
    uint16(0) == 0x5a4d and filesize < 2895KB and
    4 of them
}
    
