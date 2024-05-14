rule dfedbcefbddbbacccdaecc_exe {
strings:
        $s1 = "QGr=j\"p\\E2 $"
        $s2 = "h\\%Q&G7!\"P$C"
        $s3 = "eS&ERc4$ap["
        $s4 = "cFHqXotu2nQ"
        $s5 = "wF^:-ryN?Q`"
        $s6 = "]q/sZA+=Cm0"
        $s7 = "e-X<S9v# Qs"
        $s8 = "37}'hYXSgL,"
        $s9 = ",W_]SP1u^29"
        $s10 = "yrY!~}2,`In"
        $s11 = "8/TsrbJU`n'"
        $s12 = "~oNL/!+b,0j"
        $s13 = "/._qwfENulr"
        $s14 = "un'>d#<\"PV"
        $s15 = "iA?&B(2P4~/"
        $s16 = "I8+~.OLiF}a"
        $s17 = "$F4YKC^7_?H"
        $s18 = "D7i#ul6z9Hj"
        $s19 = "ow(e1vWUg<N"
        $s20 = "&?T(%2q.9I3"
condition:
    uint16(0) == 0x5a4d and filesize < 236KB and
    4 of them
}
    
