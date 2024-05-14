rule cdfcccaadfecfccedcafbf_dll {
strings:
        $s1 = "GetTickCount"
        $s2 = "-9IdUb*RVF"
        $s3 = "O6h$Z04Fg+"
        $s4 = "GetTempPathA"
        $s5 = "KERNEL32.dll"
        $s6 = "CreateProcessA"
        $s7 = "0ju1nR}}SE"
        $s8 = "USER32.dll"
        $s9 = "CloseHandle"
        $s10 = "CreateFileA"
        $s11 = "SetErrorMode"
        $s12 = "JS[P=-+\""
        $s13 = "ZS1@E$jM8"
        $s14 = "WS'4k#F.p"
        $s15 = "wsprintfA"
        $s16 = "v:uh~zs.0"
        $s17 = "nAS-\\L6z"
        $s18 = "Q\\#6&\\[R"
        $s19 = "WriteFile"
        $s20 = "cMMb[\\:+"
condition:
    uint16(0) == 0x5a4d and filesize < 125KB and
    4 of them
}
    
