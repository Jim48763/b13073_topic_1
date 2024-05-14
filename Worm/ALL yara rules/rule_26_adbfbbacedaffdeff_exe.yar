rule adbfbbacedaffdeff_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "_CorExeMain"
        $s9 = "Process32FirstW"
        $s10 = "ipStringToArray"
        $s11 = "wmiintegrator.exe"
        $s12 = "getThreadInterval"
        $s13 = "lzvPyuZBpOBIlWWB"
        $s14 = "get_ModuleHandle"
        $s15 = "TerminateProcess"
        $s16 = "GetExceptionCode"
        $s17 = "GetCurrentThreadId"
        $s18 = "__CxxDetectRethrow"
        $s19 = "RegexOptions"
        $s20 = "OLEAUT32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 263KB and
    4 of them
}
    
