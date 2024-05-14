rule Email_Worm_MyDoom_NF_exe {
strings:
        $s1 = "ABCDEFGHIJK"
        $s2 = "bFO><:t9.5"
        $s3 = "23456789+/"
        $s4 = "ExitProcess"
        $s5 = "ADVAPI32.dll"
        $s6 = "~E< r8<=t4<+t0<"
        $s7 = "GetProcAddress"
        $s8 = "USER32.dll"
        $s9 = "MSVCRT.dll"
        $s10 = "K?GOGSU~m3"
        $s11 = "}d4H1A|(}."
        $s12 = "comhdeRe$t"
        $s13 = "USERPROFILE"
        $s14 = "LoadLibraryA"
        $s15 = "RegCloseKey"
        $s16 = "KERNEL32.DLL"
        $s17 = "rctrl_renwn"
        $s18 = "W0RAR.v.3Z."
        $s19 = "&!Vo<SDj="
        $s20 = "wsprintfA"
condition:
    uint16(0) == 0x5a4d and filesize < 49KB and
    4 of them
}
    
