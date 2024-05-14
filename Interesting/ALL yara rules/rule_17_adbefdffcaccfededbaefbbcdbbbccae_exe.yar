rule adbefdffcaccfededbaefbbcdbbbccae_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "AuthenticationMode"
        $s3 = "STAThreadAttribute"
        $s4 = "DesignerGeneratedAttribute"
        $s5 = "ProductName"
        $s6 = "_CorExeMain"
        $s7 = "VarFileInfo"
        $s8 = "ThreadStaticAttribute"
        $s9 = "set_MinimizeBox"
        $s10 = "FileDescription"
        $s11 = "set_AutoSizeMode"
        $s12 = "AutoSaveSettings"
        $s13 = "DebuggerHiddenAttribute"
        $s14 = "InitializeComponent"
        $s15 = "CancelEventHandler"
        $s16 = "System.Media"
        $s17 = "set_TabIndex"
        $s18 = "GraphicsUnit"
        $s19 = "Synchronized"
        $s20 = "set_IsSingleInstance"
condition:
    uint16(0) == 0x5a4d and filesize < 131KB and
    4 of them
}
    
