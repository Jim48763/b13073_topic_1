rule ebdebbabfdfdbddcfdafebbeacbd_exe {
strings:
        $s1 = "'4AO[hu}pcV"
        $s2 = "B\"0= U2')c"
        $s3 = "bCn;- i9|7e"
        $s4 = "lbyLr(\">hu"
        $s5 = "DzANP,%4p}s"
        $s6 = "&uADV\"0[N^"
        $s7 = ",fxHB\"thjw"
        $s8 = "jzDLN\"Tavy"
        $s9 = ".!0_C\"|fkx"
        $s10 = "i{\"LY :cp}"
        $s11 = "zO.\"`a=W6i"
        $s12 = "8s|.>:GDe`l"
        $s13 = "GetModuleHandleW"
        $s14 = "TerminateProcess"
        $s15 = "WriteProcessMemory"
        $s16 = "GetCurrentThreadId"
        $s17 = "(5BN\\iv|obU"
        $s18 = "[HMG8+j&rG<-"
        $s19 = "GetTickCount"
        $s20 = "p,Z\"/<IVcp}"
condition:
    uint16(0) == 0x5a4d and filesize < 1085KB and
    4 of them
}
    
