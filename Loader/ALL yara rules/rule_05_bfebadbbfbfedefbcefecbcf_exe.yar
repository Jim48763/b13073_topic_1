rule bfebadbbfbfedefbcefecbcf_exe {
strings:
        $s1 = "CoInitializeEx"
        $s2 = "GetConsoleOutputCP"
        $s3 = "`local vftable'"
        $s4 = "DialogBoxParamW"
        $s5 = "TerminateProcess"
        $s6 = "SetFilePointerEx"
        $s7 = "GetCurrentThreadId"
        $s8 = "GetLocalTime"
        $s9 = "kind:picture"
        $s10 = "Sample Query"
        $s11 = "PropVariantClear"
        $s12 = "FindFirstFileExW"
        $s13 = "PKERNEL32.dll"
        $s14 = "GetWindowRect"
        $s15 = "#GG=`i^rY#6|L"
        $s16 = "support@pro-kon.ru0"
        $s17 = "Unknown exception"
        $s18 = "RtlCaptureContext"
        $s19 = "LoadLibraryExW"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 391KB and
    4 of them
}
    
