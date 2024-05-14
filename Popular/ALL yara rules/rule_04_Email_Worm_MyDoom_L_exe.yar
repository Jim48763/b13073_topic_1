rule Email_Worm_MyDoom_L_exe {
strings:
        $s1 = "Subject: %s"
        $s2 = "SetThreadPriority"
        $s3 = "GetModuleHandleA"
        $s4 = "GetLocalTime"
        $s5 = "GetTickCount"
        $s6 = "SetEndOfFile"
        $s7 = "MapViewOfFile"
        $s8 = "X-Priority: 3"
        $s9 = "CharUpperBuffA"
        $s10 = "GetTempFileNameA"
        $s11 = "ShareReactor.com"
        $s12 = "RegCreateKeyExA"
        $s13 = "GetDriveTypeA"
        $s14 = "charset=us-ascii"
        $s15 = "rctrl_renwnd32"
        $s16 = "GetProcessHeap"
        $s17 = "ExitThread"
        $s18 = "wvsprintfA"
        $s19 = "DnsQuery_A"
        $s20 = "gold-certs"
condition:
    uint16(0) == 0x5a4d and filesize < 80KB and
    4 of them
}
    
