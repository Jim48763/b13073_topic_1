rule efeacefeefbdddbdfccffddedcaadbc_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "msctls_trackbar32"
        $s3 = "LoadAcceleratorsW"
        $s4 = "Transform finish."
        $s5 = "GetTouchInputInfo"
        $s6 = "Sorry, can not do it."
        $s7 = "AfxmReleaseManagedReferences"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "RecentFrameAlignment"
        $s10 = "TextExtendedDisabled"
        $s11 = "HighlightedDisabled"
        $s12 = "CMFCRibbonMainPanel"
        $s13 = "OleLockRunning"
        $s14 = "RegSetValueExW"
        $s15 = ".?AVCPreviewView@@"
        $s16 = "GdipGetImageHeight"
        $s17 = "GetConsoleOutputCP"
        $s18 = "CoDisconnectObject"
        $s19 = "GetWindowDC"
        $s20 = "MFCLink_Url"
condition:
    uint16(0) == 0x5a4d and filesize < 2802KB and
    4 of them
}
    
