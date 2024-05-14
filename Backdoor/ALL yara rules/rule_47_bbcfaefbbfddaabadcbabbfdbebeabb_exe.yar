rule bbcfaefbbfddaabadcbabbfdbebeabb_exe {
strings:
        $s1 = "set_TransparencyKey"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "AuthenticationMode"
        $s5 = "DesignerGeneratedAttribute"
        $s6 = "My.Computer"
        $s7 = "MsgBoxStyle"
        $s8 = "get_POINTER"
        $s9 = "_CorExeMain"
        $s10 = "u6jCXbK$#Vx"
        $s11 = "4,q\"b-+'ml"
        $s12 = "ProductName"
        $s13 = "zBkUexERWDs"
        $s14 = "VarFileInfo"
        $s15 = "get_DimGray"
        $s16 = "ThreadStaticAttribute"
        $s17 = "FileDescription"
        $s18 = "set_RightToLeft"
        $s19 = "PaintEventHandler"
        $s20 = "AutoSaveSettings"
condition:
    uint16(0) == 0x5a4d and filesize < 754KB and
    4 of them
}
    
