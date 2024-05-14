rule ebccaedbebfeedafeeebacabacf_exe {
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
        $s13 = "get_ModuleHandle"
        $s14 = "TerminateProcess"
        $s15 = "GetExceptionCode"
        $s16 = "GetCurrentThreadId"
        $s17 = "__CxxDetectRethrow"
        $s18 = "XRUVeGSpOgBV"
        $s19 = "TsfvhxFHRlSv"
        $s20 = "RegexOptions"
condition:
    uint16(0) == 0x5a4d and filesize < 267KB and
    4 of them
}
    
