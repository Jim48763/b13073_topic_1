rule eacaabcfccdebcbcedcbcaeffcacdc_exe {
strings:
        $s1 = "ResultPanelBefore"
        $s2 = "@ManCtrlCmp_Error"
        $s3 = "lblLegendUnfragmented"
        $s4 = "DefPreFontName"
        $s5 = "eUp Utilities 2014"
        $s6 = "@OCM_Locked"
        $s7 = "ProductName"
        $s8 = "F1NoSuspend"
        $s9 = "your email:"
        $s10 = "Margins.Top"
        $s11 = "VarFileInfo"
        $s12 = "INVCheckBox"
        $s13 = "Brush.Style"
        $s14 = "ExtCreateRegion"
        $s15 = "lBeforeSizeHigh"
        $s16 = "SetThreadLocale"
        $s17 = "FileDescription"
        $s18 = "Setting fields..."
        $s19 = "SetThreadPriority"
        $s20 = "AutoSaveIfNotSent"
condition:
    uint16(0) == 0x5a4d and filesize < 263KB and
    4 of them
}
    
