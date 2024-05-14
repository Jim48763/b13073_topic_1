rule faeaffbdfafddeaaacffab_exe {
strings:
        $s1 = "OnContextPopup,IC"
        $s2 = "clInactiveCaption"
        $s3 = "msctls_progress32"
        $s4 = "msctls_trackbar32"
        $s5 = "TInterfacedPersistent"
        $s6 = "GetEnhMetaFilePaletteEntries"
        $s7 = "TShortCutEvent"
        $s8 = "OnMouseWheelUp"
        $s9 = "EExternalException"
        $s10 = "TContextPopupEvent"
        $s11 = " T:VY)yq%tP"
        $s12 = "TPrintScale"
        $s13 = "DragKindTEC"
        $s14 = "clBtnShadow"
        $s15 = "TOpenDialog"
        $s16 = "wqliefca_YT"
        $s17 = "fsStayOnTop"
        $s18 = "TOFNotifyEx"
        $s19 = "cG4{)F.1KMZ"
        $s20 = "MaxWidthHFC"
condition:
    uint16(0) == 0x5a4d and filesize < 830KB and
    4 of them
}
    
