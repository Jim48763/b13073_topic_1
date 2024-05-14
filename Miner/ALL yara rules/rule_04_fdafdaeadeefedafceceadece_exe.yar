rule fdafdaeadeefedafceceadece_exe {
strings:
        $s1 = "H4sIAAAAAAAEAHPLL8o1BABPFCykBQAAAA=="
        $s2 = "RuntimeHelpers"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "get_ProcessorCount"
        $s6 = "ComputeHash"
        $s7 = "get_IsAdmin"
        $s8 = "get_IsWin64"
        $s9 = "ProductName"
        $s10 = "_CorExeMain"
        $s11 = "FileDescription"
        $s12 = "get_MachineName"
        $s13 = "H4sIAAAAAAAEAAtLLSrOzM8DAF/qoXAHAAAA"
        $s14 = "Microsoft Corporation"
        $s15 = "Synchronized"
        $s16 = "H4sIAAAAAAAEAAuuLA73DzczAQCex9LCCAAAAA=="
        $s17 = "GetFolderPath"
        $s18 = "get_LocalPath"
        $s19 = "get_TotalSize"
        $s20 = "StringBuilder"
condition:
    uint16(0) == 0x5a4d and filesize < 1237KB and
    4 of them
}
    
