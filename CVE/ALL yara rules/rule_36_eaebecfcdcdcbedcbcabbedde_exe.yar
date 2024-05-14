rule eaebecfcdcdcbedcbcabbedde_exe {
strings:
        $s1 = "!Xq{BA6T4D8"
        $s2 = "/.>= 603)Qs"
        $s3 = "n/zG_PR&EQS"
        $s4 = "H.\"<tOd7g "
        $s5 = "%YxJob/win_"
        $s6 = "ScopeGu6 CQ"
        $s7 = "AI_BOOTSTRRER AND"
        $s8 = "<9wLFI/iawHv"
        $s9 = "y_GVMwkRfgSR"
        $s10 = "MSVCP140.dll"
        $s11 = "ARGETDIRyOKx"
        $s12 = "p%\",;4vD;LA"
        $s13 = "H?^/PHEv;(_@"
        $s14 = "l7Ps[B}:Hu:j"
        $s15 = "ad allocationl6|U"
        $s16 = "0CRT$XCAG4'T&"
        $s17 = "c{39(B446-591B"
        $s18 = "splwow64.e^nop"
        $s19 = "{z?yyr;99xwvov"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 954KB and
    4 of them
}
    
