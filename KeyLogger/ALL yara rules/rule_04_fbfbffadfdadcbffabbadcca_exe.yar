rule fbfbffadfdadcbffabbadcca_exe {
strings:
        $s1 = "msctls_trackbar32"
        $s2 = "TrailingTextColor"
        $s3 = "TOnGetMonthInfoEvent"
        $s4 = "OnStartDock8tC"
        $s5 = "DriveComboBox1"
        $s6 = "OnMouseWheelUp"
        $s7 = "TContextPopupEvent"
        $s8 = "LoadStringA"
        $s9 = "TBrushStyle"
        $s10 = "DockSite<jC"
        $s11 = "GetWindowDC"
        $s12 = "TOFNotifyEx"
        $s13 = "TOpenDialog"
        $s14 = "DirLabel<jC"
        $s15 = "VarFileInfo"
        $s16 = "AutoSize4~C"
        $s17 = "ProductName"
        $s18 = "fsStayOnTop"
        $s19 = "TMenuMeasureItemEvent"
        $s20 = "TMenuAnimations"
condition:
    uint16(0) == 0x5a4d and filesize < 663KB and
    4 of them
}
    
