rule cbfffddebfcaabebacafffec_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "EVariantDispatchError"
        $s3 = "TInterfacedPersistent"
        $s4 = "EVariantBadVarTypeError"
        $s5 = "ImmSetCompositionFontA"
        $s6 = "GetEnhMetaFilePaletteEntries"
        $s7 = "Directory not empty"
        $s8 = " 2001, 2002 Mike Lischke"
        $s9 = "ckRunningOrNew"
        $s10 = "OnMouseWheelUp"
        $s11 = "GetWindowTheme"
        $s12 = "TWinControlActionLink"
        $s13 = "CoCreateInstanceEx"
        $s14 = "EExternalException"
        $s15 = "TContextPopupEvent"
        $s16 = "IdException"
        $s17 = "GetWindowDC"
        $s18 = "TBrushStyle"
        $s19 = "fsStayOnTop"
        $s20 = "Medium Gray"
condition:
    uint16(0) == 0x5a4d and filesize < 714KB and
    4 of them
}
    
