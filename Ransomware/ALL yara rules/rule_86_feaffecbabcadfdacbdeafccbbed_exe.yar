rule feaffecbabcadfdacbdeafccbbed_exe {
strings:
        $s1 = "q@~ni/5Ysgb"
        $s2 = "GetModuleHandleA"
        $s3 = "/<{s\"nx)`xN"
        $s4 = "RegOpenKeyExA"
        $s5 = "S(n!-<rqU."
        $s6 = "2*-M/gQ{Fu"
        $s7 = "#r;:(z.^xY"
        $s8 = "~0x/@b W6u"
        $s9 = "1DP9GVy?zi"
        $s10 = "uhU*y#`b\""
        $s11 = "Sqi594\"oZ"
        $s12 = "}?jp*b#/ E"
        $s13 = "]+Z\"&YkddW"
        $s14 = "(KeJyqQtdds"
        $s15 = "\"{:]ep]E5"
        $s16 = "(ZSj:^'F7F"
        $s17 = "7PxPD?YHt+"
        $s18 = "k\"Ie x| v"
        $s19 = "user32.dll"
        $s20 = "F\\5+u[(5T<"
condition:
    uint16(0) == 0x5a4d and filesize < 358KB and
    4 of them
}
    
