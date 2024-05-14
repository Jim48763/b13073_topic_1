rule bbbacccbedaabccaeecadfecbebbd_exe {
strings:
        $s1 = "GuardModifierflag"
        $s2 = "ThreadAmILastThread"
        $s3 = "FlagsAttribute"
        $s4 = "RuntimeHelpers"
        $s5 = "GetProcessesByName"
        $s6 = "ThreadIsTerminated"
        $s7 = "ComputeHash"
        $s8 = "ZwCreateSection"
        $s9 = "FileDescription"
        $s10 = "ThreadCycleTime"
        $s11 = "lpApplicationName"
        $s12 = "ThreadIoPriority"
        $s13 = "dwFillAttributes"
        $s14 = "ResolveEventArgs"
        $s15 = "ThreadIdealProcessor"
        $s16 = "WriteProcessMemory"
        $s17 = "lpReturnSize"
        $s18 = "UniqueThread"
        $s19 = "lpNumWritten"
        $s20 = "GetHINSTANCE"
condition:
    uint16(0) == 0x5a4d and filesize < 78KB and
    4 of them
}
    
