rule addbcaeafdaafdacebcaaeacbdbb_exe {
strings:
        $s1 = "set_AllowFullOpen"
        $s2 = "ForwardDiagonalLinear"
        $s3 = "get_OffsetMarshaler"
        $s4 = "get_ControlDarkDark"
        $s5 = "STAThreadAttribute"
        $s6 = "get_SumKola"
        $s7 = "op_Equality"
        $s8 = "Mn ,u&;JU1W"
        $s9 = "Form1_KeyUp"
        $s10 = "_CorExeMain"
        $s11 = "ProductName"
        $s12 = "VarFileInfo"
        $s13 = "Dw8\"?s4>c#"
        $s14 = "FileDescription"
        $s15 = "KeyEventHandler"
        $s16 = "DoubleBufferPanel"
        $s17 = "set_SizeGripStyle"
        $s18 = "tbPriceHamburger"
        $s19 = "tbSumClientInput"
        $s20 = "Resource_Meter.Checker"
condition:
    uint16(0) == 0x5a4d and filesize < 843KB and
    4 of them
}
    
