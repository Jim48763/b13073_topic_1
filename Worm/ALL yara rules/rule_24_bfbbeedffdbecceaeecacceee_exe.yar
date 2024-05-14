rule bfbbeedffdbecceaeecacceee_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "CHyFxNPUMoi"
        $s9 = "_CorExeMain"
        $s10 = "Process32FirstW"
        $s11 = "ipStringToArray"
        $s12 = "wmiintegrator.exe"
        $s13 = "NwwOSjkSGmJPCkJcS"
        $s14 = "getThreadInterval"
        $s15 = "get_ModuleHandle"
        $s16 = "TerminateProcess"
        $s17 = "GetExceptionCode"
        $s18 = "GetCurrentThreadId"
        $s19 = "__CxxDetectRethrow"
        $s20 = "RegexOptions"
condition:
    uint16(0) == 0x5a4d and filesize < 263KB and
    4 of them
}
    
