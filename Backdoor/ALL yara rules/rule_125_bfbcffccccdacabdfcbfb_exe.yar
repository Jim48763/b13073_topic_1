rule bfbcffccccdacabdfcbfb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "EOutOfResources\\"
        $s4 = "TInterfacedPersistent"
        $s5 = "TShortCutEvent"
        $s6 = "TIdCoderCollection"
        $s7 = "TContextPopupEvent"
        $s8 = "GetWindowDC"
        $s9 = "@Gt)N9DA(BS"
        $s10 = "x}%ZRC,Xyz8"
        $s11 = "^WobY/ ez\""
        $s12 = "+HF^R5r\"m@"
        $s13 = "LoadStringA"
        $s14 = "Xa:WBFmQ85{"
        $s15 = "Hizb^e\"]sT"
        $s16 = "<-z/fK{%NIC"
        $s17 = "8Md+Aqy<Zjx"
        $s18 = "oGctrFnY%LX"
        $s19 = "TBrushStyle"
        $s20 = "fsStayOnTop"
condition:
    uint16(0) == 0x5a4d and filesize < 4246KB and
    4 of them
}
    
