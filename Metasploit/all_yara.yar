import pe
rule fcbabaceacafbbadbf_exe {
strings:
        $s1 = "GetConsoleOutputCP"
        $s2 = "`local vftable'"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "SetFilePointerEx"
        $s6 = "EnterCriticalSection"
        $s7 = "GetCurrentThreadId"
        $s8 = "FindFirstFileExW"
        $s9 = "LoadLibraryExW"
        $s10 = "CorExitProcess"
        $s11 = "`udt returning'"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "GetProcessHeap"
        $s14 = "AreFileApisANSI"
        $s15 = "2#5+5b5i5s8*:2:]:d:"
        $s16 = "IsProcessorFeaturePresent"
        $s17 = "operator co_await"
        $s18 = "GetCurrentProcess"
        $s19 = "!_is_double"
        $s20 = " Base Class Array'"
condition:
    uint16(0) == 0x5a4d and filesize < 106KB and
    4 of them
}
    
rule addbffaedacadedfcbdbbbab_exe {
strings:
        $s1 = "*pe.DataDirectory"
        $s2 = "*syscall.Sockaddr"
        $s3 = "*[]map[string]int"
        $s4 = "runtime.runqsteal"
        $s5 = "MinorImageVersion"
        $s6 = "timerModifiedEarliest"
        $s7 = "runtime.cansemacquire"
        $s8 = "assignEncodingAndSize"
        $s9 = "syscall.FindFirstFile"
        $s10 = "runtime.getproccount"
        $s11 = "type..eq.runtime.mOS"
        $s12 = "runtime.(*itab).init"
        $s13 = "hasScavengeCandidate"
        $s14 = "runtime.externalthreadhandler"
        $s15 = "runtime.queuefinalizer"
        $s16 = "CreateIoCompletionPort"
        $s17 = "fatal error: cgo callback before cgo call"
        $s18 = "NumberOfLineNumbers"
        $s19 = "runtime.modulesinit"
        $s20 = "runtime.dodeltimer0"
condition:
    uint16(0) == 0x5a4d and filesize < 1909KB and
    4 of them
}
    
rule aebcffcacfbdcdfffabee_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    
rule ecdcdbefccbafecbccaadadceeed_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    