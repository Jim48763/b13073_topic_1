rule fbfeeaadfddfdeabdceeabfaf_exe {
strings:
        $s1 = "FontColor_Tick"
        $s2 = "RuntimeHelpers"
        $s3 = "AuthenticationMode"
        $s4 = "STAThreadAttribute"
        $s5 = "DesignerGeneratedAttribute"
        $s6 = "ProductName"
        $s7 = "m_inScopeNs"
        $s8 = "op_Equality"
        $s9 = "MsgBoxStyle"
        $s10 = "_CorExeMain"
        $s11 = "VarFileInfo"
        $s12 = "ThreadStaticAttribute"
        $s13 = "ProcessXElement"
        $s14 = "set_MinimizeBox"
        $s15 = "FileDescription"
        $s16 = "  Microsoft 2010"
        $s17 = "AutoSaveSettings"
        $s18 = "DebuggerHiddenAttribute"
        $s19 = "InitializeComponent"
        $s20 = "CancelEventHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 429KB and
    4 of them
}
    
