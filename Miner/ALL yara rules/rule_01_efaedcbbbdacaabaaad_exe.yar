rule efaedcbbbdacaabaaad_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "RuntimeFieldHandle"
        $s3 = "STAThreadAttribute"
        $s4 = "IsClosedIDsilRMKCR"
        $s5 = "ProductName"
        $s6 = "*7x.lUprIZ;"
        $s7 = "_CorExeMain"
        $s8 = "VarFileInfo"
        $s9 = "O]a)l>t}J0g"
        $s10 = "FileDescription"
        $s11 = "GetExportedTypes"
        $s12 = "SecurityCriticalAttribute"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "IAsyncResult"
        $s15 = "IEquatable`1"
        $s16 = "Synchronized"
        $s17 = "System.Resources"
        $s18 = "StringBuilder"
        $s19 = "GeneratedCodeAttribute"
        $s20 = "ItemICWnZXWlil"
condition:
    uint16(0) == 0x5a4d and filesize < 283KB and
    4 of them
}
    
