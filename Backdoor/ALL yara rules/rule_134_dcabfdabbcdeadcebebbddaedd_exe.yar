rule dcabfdabbcdeadcebebbddaedd_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "##;%**D.99K5>>O5>>O.99K%))D"
        $s3 = "_2048.Resources.resources"
        $s4 = "set_TransparentColor"
        $s5 = "RuntimeHelpers"
        $s6 = "STAThreadAttribute"
        $s7 = "AuthenticationMode"
        $s8 = "DesignerGeneratedAttribute"
        $s9 = "MsgBoxStyle"
        $s10 = "_CorExeMain"
        $s11 = "E',{!;S3uIH"
        $s12 = "ProductName"
        $s13 = "VarFileInfo"
        $s14 = "ThreadStaticAttribute"
        $s15 = "FileDescription"
        $s16 = "KeyEventHandler"
        $s17 = "set_AutoValidate"
        $s18 = "get_ControlLight"
        $s19 = "AutoSaveSettings"
        $s20 = "DebuggerHiddenAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 523KB and
    4 of them
}
    
