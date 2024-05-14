rule feceabaddcfbaccdaacbcabdafde_exe {
strings:
        $s1 = "CreateThreadpoolTimer"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "RtlNtStatusToDosError"
        $s4 = "Handle %x created"
        $s5 = "TerminateProcess"
        $s6 = "SetFilePointerEx"
        $s7 = "SetThreadStackGuarantee"
        $s8 = "EnterCriticalSection"
        $s9 = "Out of Memory"
        $s10 = "Status: State Change"
        $s11 = "RtlCaptureContext"
        $s12 = "CorExitProcess"
        $s13 = "FormatMessageW"
        $s14 = "LoadLibraryExW"
        $s15 = "GetTempFileNameW"
        $s16 = "Request_Complete"
        $s17 = "InternetCloseHandle"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "SizeofResource"
        $s20 = "GetProcessHeap"
condition:
    uint16(0) == 0x5a4d and filesize < 256KB and
    4 of them
}
    
