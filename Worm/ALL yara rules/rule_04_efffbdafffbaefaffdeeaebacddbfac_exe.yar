rule efffbdafffbaefaffdeeaebacddbfac_exe {
strings:
        $s1 = "*:2222/CMD_LOGIN*"
        $s2 = "*twitter.com/sessions"
        $s3 = "RegSetValueExW"
        $s4 = "NtResumeThread"
        $s5 = "VirtualAllocEx"
        $s6 = "*netload.in/index*"
        $s7 = "[PDef+]: %s"
        $s8 = "DeleteSecurityContext"
        $s9 = "DeviceIoControl"
        $s10 = "bebo Lifestream"
        $s11 = "Keep-Alive: 300"
        $s12 = "*whcms*dologin*"
        $s13 = "ApplyControlToken"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleW"
        $s16 = "SetCurrentDirectoryA"
        $s17 = "WriteProcessMemory"
        $s18 = "GetAddrInfoW"
        $s19 = "FLN-Password"
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 99KB and
    4 of them
}
    
