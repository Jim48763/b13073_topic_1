rule bbbdcbbcabefafdaccbede_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "_CorExeMain"
        $s4 = "FileDescription"
        $s5 = "Synchronized"
        $s6 = "System.Resources"
        $s7 = "GeneratedCodeAttribute"
        $s8 = "defaultInstance"
        $s9 = "DebuggingModes"
        $s10 = "LegalTrademarks"
        $s11 = "Copyright "
        $s12 = "IDisposable"
        $s13 = "CultureInfo"
        $s14 = "DownloadFile"
        $s15 = "ConsoleApp42"
        $s16 = "get_Assembly"
        $s17 = "OriginalFilename"
        $s18 = "VS_VERSION_INFO"
        $s19 = "GetTempPath"
        $s20 = "resourceMan"
condition:
    uint16(0) == 0x5a4d and filesize < 11KB and
    4 of them
}
    
