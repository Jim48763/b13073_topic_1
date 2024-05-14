rule eddbabfcddecdfdebafba_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TrailingTextColor"
        $s3 = "TInterfacedPersistent"
        $s4 = "CoAddRefServerProcess"
        $s5 = "ImmSetCompositionFontA"
        $s6 = "GetEnhMetaFilePaletteEntries"
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "Database Login"
        $s9 = "CoInitializeEx"
        $s10 = "OnMouseWheelUp"
        $s11 = "ckRunningOrNew"
        $s12 = "TContextPopupEvent"
        $s13 = "TCommonCalendart+C"
        $s14 = "u0h/8msjO=:"
        $s15 = "fsStayOnTop"
        $s16 = "Medium Gray"
        $s17 = "iJ*g$Olt[Q^"
        $s18 = "TOleGraphic"
        $s19 = "TOpenDialog"
        $s20 = "X`6SRj1aNTI"
condition:
    uint16(0) == 0x5a4d and filesize < 814KB and
    4 of them
}
    
