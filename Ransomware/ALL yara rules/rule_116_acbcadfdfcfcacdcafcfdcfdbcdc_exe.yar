rule acbcadfdfcfcacdcafcfdcfdbcdc_exe {
strings:
        $s1 = "Me`(}<qp1H/"
        $s2 = "DPQqQuQ.14Z!yqZn"
        $s3 = "winspool.drv"
        $s4 = "s80(rfR5}ccu"
        $s5 = "[`|(:hk?`%<G"
        $s6 = "lQSP3Opt*\\x"
        $s7 = "EnumPrintersA"
        $s8 = "    </security>"
        $s9 = "VirtualProtect"
        $s10 = "0qprK$}7Y2"
        $s11 = "NJ<Ks*1wqW"
        $s12 = "~@(4P(4@(<P(<D(4T(4D(<T(<@(6P(6@(>P(>D(6T(6D(>T(>A(4Q(4A(<Q(<E(4U(4E(<U(<A(6Q(6A(>Q(>E(6U(6E(>U(>@"
        $s13 = "hglPlongORB\\"
        $s14 = "GetProcAddress"
        $s15 = "VirtualAlloc"
        $s16 = "Q*UP\"eQ(z"
        $s17 = "Y%>l<*Jg*F"
        $s18 = "J_[V-s#Q\\"
        $s19 = "EECz4g-ev%4"
        $s20 = "LoadLibraryA"
condition:
    uint16(0) == 0x5a4d and filesize < 421KB and
    4 of them
}
    
