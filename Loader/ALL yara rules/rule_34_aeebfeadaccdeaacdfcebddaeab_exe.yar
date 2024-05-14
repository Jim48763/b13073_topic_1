rule aeebfeadaccdeaacdfcebddaeab_exe {
strings:
        $s1 = ".==CINSYgffffmmm\\0i"
        $s2 = "999'OOOTUTO'V%J$*WQX"
        $s3 = "GetEnhMetaFilePaletteEntries"
        $s4 = "SetWindowTheme"
        $s5 = "CoInitializeEx"
        $s6 = "TContextPopupEvent"
        $s7 = "CoCreateInstanceEx"
        $s8 = "AutoSizepHC"
        $s9 = "DockSite89C"
        $s10 = "TPrintScale"
        $s11 = "Medium Gray"
        $s12 = "TDragObject"
        $s13 = "TBrushStyle"
        $s14 = "TOFNotifyEx"
        $s15 = "fsStayOnTop"
        $s16 = "LoadStringA"
        $s17 = "clBtnShadow"
        $s18 = "Window Text"
        $s19 = "GetWindowDC"
        $s20 = "TMenuMeasureItemEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 888KB and
    4 of them
}
    
