rule aefcfdbeebfecdbbebbbdffa_dll {
strings:
        $s1 = "CryptReleaseContext"
        $s2 = "CoInitializeEx"
        $s3 = "InternetCrackUrlW"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "SetFilePointerEx"
        $s7 = "GetComputerNameW"
        $s8 = "LsaGetLogonSessionData"
        $s9 = "EnterCriticalSection"
        $s10 = "OLEAUT32.dll"
        $s11 = "NtOpenThread"
        $s12 = "GetTickCount"
        $s13 = "HttpSendRequestW"
        $s14 = "NtOpenProcess"
        $s15 = "ProcessIdToSessionId"
        $s16 = "OpenSCManagerW"
        $s17 = "LoadLibraryExW"
        $s18 = "CorExitProcess"
        $s19 = "ControlService"
        $s20 = "InternetCloseHandle"
condition:
    uint16(0) == 0x5a4d and filesize < 173KB and
    4 of them
}
    
