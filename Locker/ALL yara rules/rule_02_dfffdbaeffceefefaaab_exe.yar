rule dfffdbaeffceefefaaab_exe {
strings:
        $s1 = "set_TransparencyKey"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "AuthenticationMode"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "MsgBoxStyle"
        $s8 = "My.Computer"
        $s9 = "_CorExeMain"
        $s10 = "ThreadStaticAttribute"
        $s11 = "set_MinimizeBox"
        $s12 = "get_WebBrowser1"
        $s13 = "FileDescription"
        $s14 = "set_PasswordChar"
        $s15 = "AutoSaveSettings"
        $s16 = "InitializeComponent"
        $s17 = "GraphicsUnit"
        $s18 = "set_TabIndex"
        $s19 = "Synchronized"
        $s20 = "set_ReadOnly"
condition:
    uint16(0) == 0x5a4d and filesize < 26KB and
    4 of them
}
    
