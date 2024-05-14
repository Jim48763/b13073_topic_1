rule bccfebebadbfeeecbfdbdfbcd_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TInterfacedPersistent"
        $s3 = "CoAddRefServerProcess"
        $s4 = "ImmSetCompositionFontA"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "CoInitializeEx"
        $s7 = "OnMouseWheelUp"
        $s8 = "SetWindowTheme"
        $s9 = "CoCreateInstanceEx"
        $s10 = "TContextPopupEvent"
        $s11 = "fsStayOnTop"
        $s12 = "OnDrawItem|"
        $s13 = "TBrushStyle"
        $s14 = "LoadStringA"
        $s15 = "GetWindowDC"
        $s16 = "TMenuMeasureItemEvent"
        $s17 = "TCanResizeEvent"
        $s18 = "ParentShowHintt"
        $s19 = "TResourceStream"
        $s20 = "GetKeyboardType"
condition:
    uint16(0) == 0x5a4d and filesize < 741KB and
    4 of them
}
    
