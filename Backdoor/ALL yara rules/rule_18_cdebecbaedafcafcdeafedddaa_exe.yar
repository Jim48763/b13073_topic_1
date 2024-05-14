rule cdebecbaedafcafcdeafedddaa_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "CoAddRefServerProcess"
        $s4 = "TInterfacedPersistent"
        $s5 = "EVariantBadVarTypeError"
        $s6 = "If-Unmodified-Since"
        $s7 = "Database Login"
        $s8 = "TShortCutEvent"
        $s9 = "CoCreateInstanceEx"
        $s10 = "TContextPopupEvent"
        $s11 = "GetWindowDC"
        $s12 = "Medium Gray"
        $s13 = "TGraphic,+B"
        $s14 = "Print Flags"
        $s15 = "LoadStringA"
        $s16 = "TXPManifest"
        $s17 = "Window Text"
        $s18 = "DragKindhqC"
        $s19 = "OnDrawIteml"
        $s20 = "TBrushStyle"
condition:
    uint16(0) == 0x5a4d and filesize < 1285KB and
    4 of them
}
    
