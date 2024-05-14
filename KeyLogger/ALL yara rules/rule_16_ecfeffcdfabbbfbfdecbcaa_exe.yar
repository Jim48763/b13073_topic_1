rule ecfeffcdfabbbfbfdecbcaa_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "LIuhMUi77ewcMqIwIu"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "ProductName"
        $s7 = "FileDescription"
        $s8 = "JBjs7smm1sh9JhawAJj"
        $s9 = "AssemblyTitleAttribute"
        $s10 = "nACCLlVivGaGXdvXCG"
        $s11 = "set_TabIndex"
        $s12 = "ColumnHeader"
        $s13 = "Dictionary`2"
        $s14 = "Synchronized"
        $s15 = "PerformClick"
        $s16 = "get_CurrentThread"
        $s17 = "System.Resources"
        $s18 = "AutoScaleMode"
        $s19 = "StringBuilder"
        $s20 = "PerformLayout"
condition:
    uint16(0) == 0x5a4d and filesize < 808KB and
    4 of them
}
    
