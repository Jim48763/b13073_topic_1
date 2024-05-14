rule eabdebdaebdefcdbdcddcb_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "RuntimeHelpers"
        $s3 = "get_ModuleName"
        $s4 = "GetProcessesByName"
        $s5 = "STAThreadAttribute"
        $s6 = "VDLAsh.FW,P"
        $s7 = "ProductName"
        $s8 = "op_Equality"
        $s9 = "ComputeHash"
        $s10 = "_CorExeMain"
        $s11 = "VarFileInfo"
        $s12 = "MemberRefsProxy"
        $s13 = "FlushFinalBlock"
        $s14 = "FileDescription"
        $s15 = "ResolveEventArgs"
        $s16 = "lpDebugEvent"
        $s17 = "ObjectHandle"
        $s18 = "Dictionary`2"
        $s19 = "Synchronized"
        $s20 = "IAsyncResult"
condition:
    uint16(0) == 0x5a4d and filesize < 341KB and
    4 of them
}
    
