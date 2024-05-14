rule dbfccdabebcfaacceaaa_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "FlagsAttribute"
        $s3 = "GetProcessesByName"
        $s4 = "SB1XWZHwHPBGZWQWwY"
        $s5 = "GKoF43F3PaIkGno3vI"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "ProductName"
        $s9 = "_CorExeMain"
        $s10 = "ComputeHash"
        $s11 = "op_Equality"
        $s12 = "VarFileInfo"
        $s13 = "FileDescription"
        $s14 = "FlushFinalBlock"
        $s15 = "ResolveEventArgs"
        $s16 = "get_ModuleHandle"
        $s17 = "http://localhost:8000/"
        $s18 = "Synchronized"
        $s19 = "DialogResult"
        $s20 = "Expression`1"
condition:
    uint16(0) == 0x5a4d and filesize < 830KB and
    4 of them
}
    
