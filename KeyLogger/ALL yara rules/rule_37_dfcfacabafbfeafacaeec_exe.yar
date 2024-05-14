rule dfcfacabafbfeafacaeec_exe {
strings:
        $s1 = "2kv*g<7iaqW"
        $s2 = "ld\";TQ2&w="
        $s3 = "ac'J$D&(FQl"
        $s4 = "G<\"|EB8oX "
        $s5 = "Q/Kwgz|8XyV"
        $s6 = "g0m\"j-LCK^"
        $s7 = "C Z\"j}z?tN"
        $s8 = "QwAjn?=O$qt"
        $s9 = "ZwlDrK(TkGL"
        $s10 = "X^KFW\"pU.b"
        $s11 = ">X<itj(hRK_"
        $s12 = "BfZ^I 2q'YT"
        $s13 = "7AEp3!<}(L|"
        $s14 = "`j\"8sB9-aE"
        $s15 = "jI$!V%\"dKf"
        $s16 = "8Wu2 #_0L'/"
        $s17 = "ReadProcessMemory"
        $s18 = "GetModuleHandleA"
        $s19 = "|EHeOG=e/lqW"
        $s20 = "bG[URe/C=euT"
condition:
    uint16(0) == 0x5a4d and filesize < 4994KB and
    4 of them
}
    
