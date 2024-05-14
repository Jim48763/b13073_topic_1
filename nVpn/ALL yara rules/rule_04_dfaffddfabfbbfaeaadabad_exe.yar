rule dfaffddfabfbbfaeaadabad_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "_CorExeMain"
        $s5 = "FileDescription"
        $s6 = "set_TabIndex"
        $s7 = "Dictionary`2"
        $s8 = "Synchronized"
        $s9 = "get_CurrentThread"
        $s10 = "System.Resources"
        $s11 = "MethodInvoker"
        $s12 = "StringBuilder"
        $s13 = "get_ManagedThreadId"
        $s14 = "GeneratedCodeAttribute"
        $s15 = "Pzoxcuuwrc9.exe"
        $s16 = "defaultInstance"
        $s17 = "ReferenceEquals"
        $s18 = "CompressionMode"
        $s19 = "ResourceManager"
        $s20 = "GZipStream"
condition:
    uint16(0) == 0x5a4d and filesize < 431KB and
    4 of them
}
    
