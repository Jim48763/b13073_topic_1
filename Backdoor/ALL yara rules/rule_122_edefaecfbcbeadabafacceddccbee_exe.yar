rule edefaecfbcbeadabafacceddccbee_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "EOutOfResources\\"
        $s4 = "TInterfacedPersistent"
        $s5 = "TShortCutEvent"
        $s6 = "m@I+++1*\"_}M0"
        $s7 = "TIdCoderCollection"
        $s8 = "TContextPopupEvent"
        $s9 = "GetWindowDC"
        $s10 = "v98YXFWlm*N"
        $s11 = "LoadStringA"
        $s12 = "TBrushStyle"
        $s13 = "fsStayOnTop"
        $s14 = "0|=_-n6d1}4"
        $s15 = "TMenuMeasureItemEvent"
        $s16 = "TCustomGroupBox"
        $s17 = "GetThreadLocale"
        $s18 = "ooDrawFocusRect"
        $s19 = "TMenuAnimations"
        $s20 = "TCanResizeEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 843KB and
    4 of them
}
    
