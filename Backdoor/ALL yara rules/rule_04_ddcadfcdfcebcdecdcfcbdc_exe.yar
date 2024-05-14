rule ddcadfcdfcebcdecdcfcbdc_exe {
strings:
        $s1 = "add_MdiChildActivate"
        $s2 = "DescriptionAttribute"
        $s3 = "ResetMouseEventArgs"
        $s4 = "FlagsAttribute"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "_CorExeMain"
        $s8 = "ComputeHash"
        $s9 = "ProductName"
        $s10 = "VarFileInfo"
        $s11 = "y%#bo<8kR i"
        $s12 = "FileDescription"
        $s13 = "set_RightToLeft"
        $s14 = "IFormatProvider"
        $s15 = "get_ColorScheme"
        $s16 = "AddMessageFilter"
        $s17 = "ContextMenuStrip"
        $s18 = " Weifen Luo 2007"
        $s19 = "DebuggerHiddenAttribute"
        $s20 = "UnhookWindowsHookEx"
condition:
    uint16(0) == 0x5a4d and filesize < 289KB and
    4 of them
}
    
