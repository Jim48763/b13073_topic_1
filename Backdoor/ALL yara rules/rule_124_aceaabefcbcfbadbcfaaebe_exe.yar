rule aceaabefcbcfbadbcfaaebe_exe {
strings:
        $s1 = "EOutOfResources\\"
        $s2 = "GetKeyboardLayout"
        $s3 = "TInterfacedPersistent"
        $s4 = "ImmSetCompositionFontA"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "TWinControlActionLink"
        $s7 = "EExternalException"
        $s8 = "TContextPopupEvent"
        $s9 = "TIdCoderCollection"
        $s10 = "IdException"
        $s11 = "GetWindowDC"
        $s12 = "AutoSize@(C"
        $s13 = "TBrushStyle"
        $s14 = "fsStayOnTop"
        $s15 = "O:IjrY6g{#>"
        $s16 = "LoadStringA"
        $s17 = "TMenuMeasureItemEvent"
        $s18 = "TCustomGroupBox"
        $s19 = "TMenuActionLink"
        $s20 = "ooDrawFocusRect"
condition:
    uint16(0) == 0x5a4d and filesize < 843KB and
    4 of them
}
    
