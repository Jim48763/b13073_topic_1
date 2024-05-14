rule fabbdeceabcecfcafaebdcbaf_exe {
strings:
        $s1 = "NetCostSample.exe"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "CoInitializeEx"
        $s4 = "`local vftable'"
        $s5 = "TerminateProcess"
        $s6 = "SetFilePointerEx"
        $s7 = "DispatchMessageW"
        $s8 = "SetThreadStackGuarantee"
        $s9 = "lGL(,g=7Xh{g"
        $s10 = "GetLocalTime"
        $s11 = "GetAddrInfoW"
        $s12 = "Unknown exception"
        $s13 = "RtlCaptureContext"
        $s14 = "LoadLibraryExW"
        $s15 = "CorExitProcess"
        $s16 = "`udt returning'"
        $s17 = "    </security>"
        $s18 = "DeleteCriticalSection"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "Error Code: 0x%x"
condition:
    uint16(0) == 0x5a4d and filesize < 370KB and
    4 of them
}
    
