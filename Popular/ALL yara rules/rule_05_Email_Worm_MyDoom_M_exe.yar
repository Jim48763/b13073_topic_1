rule Email_Worm_MyDoom_M_exe {
strings:
        $s1 = "Subject: %s"
        $s2 = "FMPWDHOUEJQ"
        $s3 = "SetThreadPriority"
        $s4 = "GetModuleHandleA"
        $s5 = "GetLocalTime"
        $s6 = "GetTickCount"
        $s7 = "MapViewOfFile"
        $s8 = "X-Priority: 3"
        $s9 = "CharUpperBuffA"
        $s10 = "GetTempFileNameA"
        $s11 = "RegCreateKeyExA"
        $s12 = "GetDriveTypeA"
        $s13 = "$8AAA6213(/5'"
        $s14 = "charset=us-ascii"
        $s15 = "rctrl_renwnd32"
        $s16 = "GetProcessHeap"
        $s17 = "cd2cFdoy9od\"@A"
        $s18 = "ExitThread"
        $s19 = "wvsprintfA"
        $s20 = "DnsQuery_A"
condition:
    uint16(0) == 0x5a4d and filesize < 45KB and
    4 of them
}
    
