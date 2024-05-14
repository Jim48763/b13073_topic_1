rule cdacebfcabdfabfdbafbefea_exe {
strings:
        $s1 = "SchemaDecoratorComp"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "System.Linq"
        $s5 = "op_Equality"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "FileDescription"
        $s9 = "Synchronized"
        $s10 = "DialogResult"
        $s11 = "System.Resources"
        $s12 = "ExtensionAttribute"
        $s13 = "GeneratedCodeAttribute"
        $s14 = "_Configuration"
        $s15 = "defaultInstance"
        $s16 = "set_StartInfo"
        $s17 = "DebuggingModes"
        $s18 = "LegalTrademarks"
        $s19 = "PostBridge"
        $s20 = "FromSeconds"
condition:
    uint16(0) == 0x5a4d and filesize < 22KB and
    4 of them
}
    
