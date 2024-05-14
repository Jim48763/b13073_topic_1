rule cbfffddebfcaabebacafffec_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TInterfacedPersistent"
        $s3 = "CoAddRefServerProcess"
        $s4 = "ImmSetCompositionFontA"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "Directory not empty"
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "CoInitializeEx"
        $s9 = "OnMouseWheelUp"
        $s10 = "SetWindowTheme"
        $s11 = "ckRunningOrNew"
        $s12 = "TContextPopupEvent"
        $s13 = "WSAJoinLeaf"
        $s14 = "fsStayOnTop"
        $s15 = "Medium Gray"
        $s16 = "TOleGraphic"
        $s17 = "WSARecvFrom"
        $s18 = "TBrushStyle"
        $s19 = "LoadStringA"
        $s20 = ")IdWinSock2"
condition:
    uint16(0) == 0x5a4d and filesize < 714KB and
    4 of them
}
    
