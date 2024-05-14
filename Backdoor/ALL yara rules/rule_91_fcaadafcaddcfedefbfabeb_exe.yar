rule fcaadafcaddcfedefbfabeb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "TInterfacedPersistent"
        $s4 = "TShortCutEvent"
        $s5 = "TbbbKF+je;|c$A"
        $s6 = "OnMouseWheelUp"
        $s7 = "TContextPopupEvent"
        $s8 = "GetWindowDC"
        $s9 = "s&8?iYm\"Qg"
        $s10 = "LoadStringA"
        $s11 = "#51SJW$(go|"
        $s12 = "TBrushStyle"
        $s13 = "fsStayOnTop"
        $s14 = "TClipboardt"
        $s15 = "TMenuMeasureItemEvent"
        $s16 = "TCustomDockForm"
        $s17 = "TCustomGroupBox"
        $s18 = "GetThreadLocale"
        $s19 = "ooDrawFocusRect"
        $s20 = "TMenuAnimations"
condition:
    uint16(0) == 0x5a4d and filesize < 786KB and
    4 of them
}
    
