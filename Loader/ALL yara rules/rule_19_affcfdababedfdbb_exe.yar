rule affcfdababedfdbb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TInterfacedPersistent"
        $s3 = "EVariantBadVarTypeError"
        $s4 = "clWebLightSteelBlue"
        $s5 = " 2001, 2002 Mike Lischke"
        $s6 = "SetWindowTheme"
        $s7 = "clWebOrangeRed"
        $s8 = "TWinControlActionLink"
        $s9 = "TContextPopupEvent"
        $s10 = "TPrintScale"
        $s11 = "TDragObject"
        $s12 = "TBrushStyle"
        $s13 = "DockSite,4C"
        $s14 = "Layout File"
        $s15 = "fsStayOnTop"
        $s16 = "LoadStringA"
        $s17 = "clWebIndigo"
        $s18 = "clBtnShadow"
        $s19 = "GetWindowDC"
        $s20 = "TMenuMeasureItemEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 816KB and
    4 of them
}
    
