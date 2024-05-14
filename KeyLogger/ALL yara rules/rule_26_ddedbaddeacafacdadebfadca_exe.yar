rule ddedbaddeacafacdadebfadca_exe {
strings:
        $s1 = "TInterfacedPersistent"
        $s2 = "TSilentPaintPanelX,C"
        $s3 = " 2001, 2002 Mike Lischke"
        $s4 = "CoInitializeEx"
        $s5 = "CoCreateInstanceEx"
        $s6 = "TMSDOMNamedNodeMap"
        $s7 = "TContextPopupEvent"
        $s8 = "Window Text"
        $s9 = "LoadStringA"
        $s10 = "MaxWidth`zC"
        $s11 = "TBrushStyle"
        $s12 = "GetWindowDC"
        $s13 = "TOFNotifyEx"
        $s14 = "DragKind yC"
        $s15 = "TDragObject"
        $s16 = "Interval|VA"
        $s17 = "Medium Gray"
        $s18 = "fsStayOnTop"
        $s19 = "TMenuMeasureItemEvent"
        $s20 = "TMenuAnimations"
condition:
    uint16(0) == 0x5a4d and filesize < 632KB and
    4 of them
}
    
