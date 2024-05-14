rule bbfecfeaafdceaeaafebfcbfcaefcc_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "TStringSparseList"
        $s3 = "EVariantDispatchError"
        $s4 = "TInterfacedPersistent"
        $s5 = "EVariantBadVarTypeError"
        $s6 = "ImmSetCompositionFontA"
        $s7 = "GetEnhMetaFilePaletteEntries"
        $s8 = " 2001, 2002 Mike Lischke"
        $s9 = "OnMouseWheelUp"
        $s10 = "GetWindowTheme"
        $s11 = "search process if desired. "
        $s12 = "EExternalException"
        $s13 = "TContextPopupEvent"
        $s14 = "TStrings|*A"
        $s15 = "GetWindowDC"
        $s16 = "OpenDialog1"
        $s17 = "TBrushStyle"
        $s18 = "fsStayOnTop"
        $s19 = "Medium Gray"
        $s20 = "TOFNotifyEx"
condition:
    uint16(0) == 0x5a4d and filesize < 658KB and
    4 of them
}
    
