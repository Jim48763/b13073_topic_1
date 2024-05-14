rule ecbcbfefcaecdebbcfaeed_exe {
strings:
        $s1 = ",;<ZqPn8ht'"
        $s2 = "w(9TD_@S75#"
        $s3 = "RDiy9GI1n\""
        $s4 = "A\"6,=K5d4O"
        $s5 = "v D_AFM;c]m"
        $s6 = "F= co-V3BfW"
        $s7 = "V9y#68mt+J`"
        $s8 = "t=3kd[\"G92"
        $s9 = "D /hQ1xvM5K"
        $s10 = "!}a]Ypg$W\""
        $s11 = "L/d$|g)4VH9"
        $s12 = "Gu*QRc-@Nhj"
        $s13 = "ReadProcessMemory"
        $s14 = "GetModuleHandleA"
        $s15 = "e-p&OH#,H%VA"
        $s16 = "1`KzvM~k\\$-"
        $s17 = "bpI\\xqN.;]L"
        $s18 = "Qx8V3NDVO1\""
        $s19 = "5~pMTi\\?nK#"
        $s20 = "WTSAPI32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 5008KB and
    4 of them
}
    
