rule bcefdbdceebfdeefdbcadebfbb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "EOutOfResources\\"
        $s4 = "TInterfacedPersistent"
        $s5 = "TShortCutEvent"
        $s6 = "TIdCoderCollection"
        $s7 = "TContextPopupEvent"
        $s8 = "GetWindowDC"
        $s9 = "p!tu$69:]Z("
        $s10 = "LoadStringA"
        $s11 = "Na^Ap c#J-n"
        $s12 = "TBrushStyle"
        $s13 = "fsStayOnTop"
        $s14 = "z ]QW#&^bi*"
        $s15 = "TMenuMeasureItemEvent"
        $s16 = "TCustomGroupBox"
        $s17 = "GetThreadLocale"
        $s18 = "ooDrawFocusRect"
        $s19 = "TMenuAnimations"
        $s20 = "TCanResizeEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 1769KB and
    4 of them
}
    
