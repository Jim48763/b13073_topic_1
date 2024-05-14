rule dbdafecdcdbaaedfeadaee_exe {
strings:
        $s1 = "BufferedPaintInit"
        $s2 = "GetKeyboardLayout"
        $s3 = "GetTouchInputInfo"
        $s4 = "LoadAcceleratorsW"
        $s5 = "msctls_trackbar32"
        $s6 = "Sorry, can not do it."
        $s7 = "GradientStartNormal"
        $s8 = "AfxmReleaseManagedReferences"
        $s9 = "SetDefaultDllDirectories"
        $s10 = "TextExtendedDisabled"
        $s11 = "RecentFrameAlignment"
        $s12 = "CMFCRibbonMainPanel"
        $s13 = "HighlightedDisabled"
        $s14 = "CMFCToolBarFontComboBox"
        $s15 = "OleLockRunning"
        $s16 = "GetWindowTheme"
        $s17 = "RegSetValueExW"
        $s18 = "GetConsoleOutputCP"
        $s19 = "CoDisconnectObject"
        $s20 = "BeginBufferedPaint"
condition:
    uint16(0) == 0x5a4d and filesize < 2755KB and
    4 of them
}
    
