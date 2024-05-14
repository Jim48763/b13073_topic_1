rule dedaadaddfaadffdbcccddafcbfb_exe {
strings:
        $s1 = "SetConsoleOutputCP"
        $s2 = "`local vftable'"
        $s3 = "AFX_DIALOG_LAYOUT"
        $s4 = "SetFilePointerEx"
        $s5 = "TerminateProcess"
        $s6 = "WriteProfileSectionW"
        $s7 = "GetCurrentThreadId"
        $s8 = "SetEndOfFile"
        $s9 = "GetTickCount"
        $s10 = "FindFirstFileExA"
        $s11 = "GetThreadContext"
        $s12 = "MapViewOfFile"
        $s13 = "CorExitProcess"
        $s14 = "LoadLibraryExW"
        $s15 = "CreateMailslotW"
        $s16 = "`udt returning'"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetProcessHeap"
        $s19 = "AreFileApisANSI"
        $s20 = "\"t<k`8W!d"
condition:
    uint16(0) == 0x5a4d and filesize < 215KB and
    4 of them
}
    
