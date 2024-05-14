rule edbfcaacdccdfbabedfedc_exe {
strings:
        $s1 = "add_PowerModeChanged"
        $s2 = "STAThreadAttribute"
        $s3 = "set_FileNameFormat"
        $s4 = "System.Linq"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "op_Equality"
        $s9 = "get_IsCompleted"
        $s10 = "set_MinimizeBox"
        $s11 = "FileDescription"
        $s12 = "set_RightToLeft"
        $s13 = "CompressionLevel"
        $s14 = "InitializeComponent"
        $s15 = "GraphicsUnit"
        $s16 = "set_TabIndex"
        $s17 = "Synchronized"
        $s18 = "set_ReadOnly"
        $s19 = "get_MainHost"
        $s20 = "<>t__builder"
condition:
    uint16(0) == 0x5a4d and filesize < 425KB and
    4 of them
}
    
