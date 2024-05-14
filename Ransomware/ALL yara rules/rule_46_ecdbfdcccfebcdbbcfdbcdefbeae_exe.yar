rule ecdbfdcccfebcdbbcfdbcdefbeae_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "VarFileInfo"
        $s3 = "%Copyright "
        $s4 = "ProductName"
        $s5 = "_CorExeMain"
        $s6 = "op_Equality"
        $s7 = "FileDescription"
        $s8 = "GetExportedTypes"
        $s9 = "Synchronized"
        $s10 = "System.Resources"
        $s11 = "GeneratedCodeAttribute"
        $s12 = "    </security>"
        $s13 = "DebuggingModes"
        $s14 = "ResourceManager"
        $s15 = "LegalTrademarks"
        $s16 = "DebuggableAttribute"
        $s17 = "CultureInfo"
        $s18 = "IDisposable"
        $s19 = "</assembly>"
        $s20 = "    <application>"
condition:
    uint16(0) == 0x5a4d and filesize < 80KB and
    4 of them
}
    
