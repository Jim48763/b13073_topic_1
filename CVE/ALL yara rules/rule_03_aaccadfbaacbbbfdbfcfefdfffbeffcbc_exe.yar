rule aaccadfbaacbbbfdbfcfefdfffbeffcbc_exe {
strings:
        $s1 = "Release object %p"
        $s2 = "QueryDosDeviceW"
        $s3 = "`local vftable'"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "SetFilePointerEx"
        $s7 = "GetCurrentThreadId"
        $s8 = "OLEAUT32.dll"
        $s9 = "FindFirstFileExW"
        $s10 = "StringFromIID"
        $s11 = "ProcessIdToSessionId"
        $s12 = "Unknown exception"
        $s13 = "RtlCaptureContext"
        $s14 = "LoadLibraryExW"
        $s15 = "FormatMessageW"
        $s16 = "`udt returning'"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "CoTaskMemFree"
        $s19 = ".?AV_com_error@@"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 162KB and
    4 of them
}
    
