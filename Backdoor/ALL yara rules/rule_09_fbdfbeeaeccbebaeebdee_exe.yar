rule fbdfbeeaeccbebaeebdee_exe {
strings:
        $s1 = "ProductName"
        $s2 = "op_Equality"
        $s3 = "VarFileInfo"
        $s4 = "_CorExeMain"
        $s5 = "FileDescription"
        $s6 = "http://google.com"
        $s7 = "GetExportedTypes"
        $s8 = "Synchronized"
        $s9 = "IncludeDefinition"
        $s10 = "CustomizeDefinition"
        $s11 = "System.Resources"
        $s12 = "/C timeout 20"
        $s13 = "GeneratedCodeAttribute"
        $s14 = "defaultInstance"
        $s15 = "DebuggingModes"
        $s16 = "LegalTrademarks"
        $s17 = "IDisposable"
        $s18 = "*kqplk2\"Z9"
        $s19 = "CultureInfo"
        $s20 = "</assembly>"
condition:
    uint16(0) == 0x5a4d and filesize < 33KB and
    4 of them
}
    
