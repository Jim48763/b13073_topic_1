rule Joke_ChilledWindows_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "RuntimeFieldHandle"
        $s4 = "[D.k\"TiA8L"
        $s5 = "T.*{u7ncV^j"
        $s6 = "YV1\"8T_j2v"
        $s7 = "Lwz\">f`&'S"
        $s8 = ">2:@91h[As3"
        $s9 = "X5@y\"}qQHL"
        $s10 = "vl_oE7a`)@2"
        $s11 = "ProductName"
        $s12 = ">VBxzrTa<]R"
        $s13 = "kw\"S!*=LJs"
        $s14 = "C\"XzOZ-nMQ"
        $s15 = "sA&.m=ZpxI6"
        $s16 = "k}>Y,AS<.{q"
        $s17 = ">\"XI8/$9ru"
        $s18 = "_CorExeMain"
        $s19 = "IXRd_^jyGT1"
        $s20 = "Lk-|B] t8F1"
condition:
    uint16(0) == 0x5a4d and filesize < 4476KB and
    4 of them
}
    
