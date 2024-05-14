rule Trojan_MrsMajor__exe {
strings:
        $s1 = "@\\DFlDG4C4$?5dCG"
        $s2 = "majordared.Properties"
        $s3 = "[iyWisZjn_pniunszms"
        $s4 = "x.run \"\"\"\"&buhu&\"\\notmuch.exe\"\"\""
        $s5 = "set_TransparencyKey"
        $s6 = "Gt0\\)H27I*i\""
        $s7 = "CD?s&pB,lBRSB8"
        $s8 = "rj!l@!4b!#TA0I"
        $s9 = "0\"!/.l!@,A!~)"
        $s10 = "y[ysZnpVlf^yeT"
        $s11 = "Ab8\"Ao7iAy6vB"
        $s12 = "SetConsoleCtrlHandler"
        $s13 = "v2eprogrampathname"
        $s14 = "STAThreadAttribute"
        $s15 = ",!D(Ws] @_I"
        $s16 = "&}zTfV_8#- "
        $s17 = "CK9-A28~>X7"
        $s18 = "Cd4_Vu%`Gn "
        $s19 = "&R+-Lb1Tk0X"
        $s20 = "<+862>*G\"N"
condition:
    uint16(0) == 0x5a4d and filesize < 26265KB and
    4 of them
}
    
