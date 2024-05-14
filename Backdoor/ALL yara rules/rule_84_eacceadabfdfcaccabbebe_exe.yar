rule eacceadabfdfcaccabbebe_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "FlagsAttribute"
        $s3 = "$this.GridSize"
        $s4 = "RuntimeHelpers"
        $s5 = "GetProcessesByName"
        $s6 = "STAThreadAttribute"
        $s7 = "ProductName"
        $s8 = "ComputeHash"
        $s9 = "My.Computer"
        $s10 = "_E=GXI;kY&N"
        $s11 = "VarFileInfo"
        $s12 = "_CorExeMain"
        $s13 = "ThreadStaticAttribute"
        $s14 = "FlushFinalBlock"
        $s15 = "MemberRefsProxy"
        $s16 = "FileDescription"
        $s17 = "WebClientProtocol"
        $s18 = "customCultureName"
        $s19 = "get_ServicePoint"
        $s20 = "DebuggerHiddenAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 338KB and
    4 of them
}
    
