rule dddeabdabfdcbbeceeddebdfe_exe {
strings:
        $s1 = "invalid string position"
        $s2 = "_crt_debugger_hook"
        $s3 = "GetModuleHandleW"
        $s4 = "Found resource 2 found"
        $s5 = "GetCurrentThreadId"
        $s6 = "_CrtSetCheckCount"
        $s7 = "_invoke_watson"
        $s8 = "The variable '"
        $s9 = "LoadLibraryExW"
        $s10 = "    </security>"
        $s11 = "Greater Manchester1"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "RegOpenKeyExW"
        $s14 = "SizeofResource"
        $s15 = "GetProcessHeap"
        $s16 = "Salisbury1"
        $s17 = "Hglob is not nutll"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "user32.dllN"
        $s20 = "Project1.ex"
condition:
    uint16(0) == 0x5a4d and filesize < 78KB and
    4 of them
}
    
