rule aafdfeeafabffddaafbaeecbcadcaffb_exe {
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
        $s13 = "LoadLibraryExW"
        $s14 = "FormatMessageW"
        $s15 = "`udt returning'"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "CoTaskMemFree"
        $s18 = ".?AV_com_error@@"
        $s19 = "OpenProcessToken"
        $s20 = "JobTransferred"
condition:
    uint16(0) == 0x5a4d and filesize < 136KB and
    4 of them
}
    
