rule debcaeccadabdadbfdcebd_exe {
strings:
        $s1 = "TInterfacedPersistent"
        $s2 = "EVariantBadVarTypeError"
        $s3 = " 2001, 2002 Mike Lischke"
        $s4 = "ckRunningOrNew"
        $s5 = "CoInitializeEx"
        $s6 = "OnMouseWheelUp"
        $s7 = "Database Login"
        $s8 = "TWinControlActionLink"
        $s9 = "CoCreateInstanceEx"
        $s10 = "TContextPopupEvent"
        $s11 = "TabsPerRowH"
        $s12 = "Window Text"
        $s13 = "LoadStringA"
        $s14 = "TBrushStyle"
        $s15 = "TStringDesc"
        $s16 = "GetWindowDC"
        $s17 = "TBoundLabel"
        $s18 = "TOleGraphic"
        $s19 = "TDragObject"
        $s20 = "Medium Gray"
condition:
    uint16(0) == 0x5a4d and filesize < 651KB and
    4 of them
}
    
