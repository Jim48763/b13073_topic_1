rule baeacbaeddcbceeaabadeaebda_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "EVariantDispatchError"
        $s3 = "TInterfacedPersistent"
        $s4 = "EVariantBadVarTypeError"
        $s5 = "ImmSetCompositionFontA"
        $s6 = "9 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9\\<}<j="
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "TShortCutEvent"
        $s9 = "OnMouseWheelUp"
        $s10 = "GetWindowTheme"
        $s11 = "EExternalException"
        $s12 = "TContextPopupEvent"
        $s13 = "GetWindowDC"
        $s14 = "TBrushStyle"
        $s15 = "fsStayOnTop"
        $s16 = "TMacroEvent"
        $s17 = "Medium Gray"
        $s18 = "LoadStringA"
        $s19 = "E/W]pmYnb} "
        $s20 = "TMenuMeasureItemEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 591KB and
    4 of them
}
    
