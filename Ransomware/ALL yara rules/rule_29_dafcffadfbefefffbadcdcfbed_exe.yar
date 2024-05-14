rule dafcffadfbefefffbadcdcfbed_exe {
strings:
        $s1 = "\\Program Files\\"
        $s2 = "Control Panel\\International"
        $s3 = "HttpAddRequestHeadersW"
        $s4 = "CryptReleaseContext"
        $s5 = "RegSetValueExW"
        $s6 = "productName"
        $s7 = "fabian wosar <3"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "mydesktopqos.exe"
        $s11 = "GetComputerNameW"
        $s12 = "DispatchMessageW"
        $s13 = "InitializeCriticalSection"
        $s14 = "infopath.exe"
        $s15 = "GetTickCount"
        $s16 = "UpdateWindow"
        $s17 = "HttpSendRequestW"
        $s18 = "MapViewOfFile"
        $s19 = "VerifyVersionInfoW"
        $s20 = "ocautoupds.exe"
condition:
    uint16(0) == 0x5a4d and filesize < 75KB and
    4 of them
}
    
