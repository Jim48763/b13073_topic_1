rule dcdfcfbefeffcdcecadadfdffacd_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TComponentNametyA"
        $s3 = "TInterfacedPersistent"
        $s4 = "TCustomControlActionl"
        $s5 = " visit the website for more info "
        $s6 = "clWebLightSteelBlue"
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "SetWindowTheme"
        $s9 = "TShortCutListd"
        $s10 = "clWebOrangeRed"
        $s11 = "OnMouseWheelUp"
        $s12 = "TWinControlActionLink"
        $s13 = "TContextPopupEvent"
        $s14 = "TCustomTabControll"
        $s15 = "TPrintScale"
        $s16 = "TDragObject"
        $s17 = "TBrushStyle"
        $s18 = "Layout File"
        $s19 = "fsStayOnTop"
        $s20 = "clWebIndigo"
condition:
    uint16(0) == 0x5a4d and filesize < 817KB and
    4 of them
}
    
