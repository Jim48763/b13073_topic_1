rule Email_Worm_MyDoom_A_exe {
strings:
        $s1 = "pqrstNwxyzg"
        $s2 = "-tvey-2.0oqp"
        $s3 = "op)NamLSPoG%"
        $s4 = "notepad %s"
        $s5 = "GSizeZClos"
        $s6 = "ExitProcess"
        $s7 = "NB;788=EP^o"
        $s8 = "ADVAPI32.dll"
        $s9 = "\\Jvaqbjf\\Phe"
        $s10 = "GetProcAddress"
        $s11 = "USER32.dll"
        $s12 = "MSVCRT.dll"
        $s13 = "5vmb/xH*.*"
        $s14 = "HByt\"nAdn"
        $s15 = "gkF0Sgnfxz"
        $s16 = "D\"veTyp$v"
        $s17 = "6[pl93foo/["
        $s18 = "LoadLibraryA"
        $s19 = "RegCloseKey"
        $s20 = "-TRG / UGGC/V"
condition:
    uint16(0) == 0x5a4d and filesize < 27KB and
    4 of them
}
    
