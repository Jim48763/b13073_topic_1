rule dbacdbbdcfddbedddfcecdfdeabe_dll {
strings:
        $s1 = "GetTickCount"
        $s2 = "FemaleCaution"
        $s3 = "RtlGetVersion"
        $s4 = "; Session_id="
        $s5 = "WinHttpReceiveResponse"
        $s6 = "ViolinAlmost32"
        $s7 = "GetProcessHeap"
        $s8 = "SHLWAPI.dll"
        $s9 = "ShowDialogA"
        $s10 = "WinHttpReadData"
        $s11 = "InformFork32"
        $s12 = "GetTempPathA"
        $s13 = "HurtCommon32"
        $s14 = "ADVAPI32.dll"
        $s15 = "GetProcAddress"
        $s16 = "GetUserNameW"
        $s17 = "SaltFantasy32"
        $s18 = "Cookie: __io_r="
        $s19 = "WinHttpConnect"
        $s20 = "WinHttpSetOption"
condition:
    uint16(0) == 0x5a4d and filesize < 16KB and
    4 of them
}
    
