rule cefeadeffbafffbcfcececaad_exe {
strings:
        $s1 = "ExitProcess"
        $s2 = "KERNEL32.dll"
        $s3 = "I\\|r)Bd{#"
        $s4 = "SetErrorMode"
        $s5 = "\"h\\i RBU"
        $s6 = ":6RBVF*T|"
        $s7 = "PQ2E_|dv:"
        $s8 = "o\\f!j+^C"
        $s9 = "-@h2Ob=2<"
        $s10 = "1A},}ZI*P"
        $s11 = "qPz-^x:\\"
        $s12 = "5f&\\2.\""
        $s13 = "hk/(OGu`"
        $s14 = "-BM|)7dD"
        $s15 = "Vx[@Xn$T"
        $s16 = "o[jaB0:#"
        $s17 = "@qI]GUev"
        $s18 = "mE9S{1A#"
        $s19 = "QwBifzUD"
        $s20 = "}(@an@2w"
condition:
    uint16(0) == 0x5a4d and filesize < 70KB and
    4 of them
}
    
