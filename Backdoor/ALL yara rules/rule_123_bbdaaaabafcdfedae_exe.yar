rule bbdaaaabafcdfedae_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "TrailingTextColor"
        $s3 = "EVariantDispatchError"
        $s4 = "TInterfacedPersistent"
        $s5 = "EVariantBadVarTypeError"
        $s6 = "ImmSetCompositionFontA"
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "OnMouseWheelUp"
        $s9 = "OnMeasureItemh"
        $s10 = "GetWindowTheme"
        $s11 = "TWinControlActionLink"
        $s12 = "EExternalException"
        $s13 = "TContextPopupEvent"
        $s14 = "TAnimate<~B"
        $s15 = "GetWindowDC"
        $s16 = "OpenDialog1"
        $s17 = "TBrushStyle"
        $s18 = "fsStayOnTop"
        $s19 = "Medium Gray"
        $s20 = "AutoSize|*C"
condition:
    uint16(0) == 0x5a4d and filesize < 773KB and
    4 of them
}
    
