rule eadaebfadadacdafbfcfec_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "op_Equality"
        $s4 = "_CorExeMain"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "get_ProcessName"
        $s9 = "DealerLimitExceeded"
        $s10 = "Synchronized"
        $s11 = "set_TabIndex"
        $s12 = "GraphicsUnit"
        $s13 = "DialogResult"
        $s14 = "GetHINSTANCE"
        $s15 = "ShowFullHand"
        $s16 = "OutputDebugString"
        $s17 = "get_CurrentThread"
        $s18 = "System.Resources"
        $s19 = "AutoScaleMode"
        $s20 = "PerformLayout"
condition:
    uint16(0) == 0x5a4d and filesize < 479KB and
    4 of them
}
    