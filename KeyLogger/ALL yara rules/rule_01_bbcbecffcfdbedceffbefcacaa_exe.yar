rule bbcbecffcfdbedceffbefcacaa_exe {
strings:
        $s1 = "OnContextPopupDBD"
        $s2 = "TControlCanvasT;D"
        $s3 = "rfCommonStartMenu"
        $s4 = "Unable to insert an item"
        $s5 = " 2001, 2002 Mike Lischke"
        $s6 = "CoInitializeEx"
        $s7 = "CoCreateInstanceEx"
        $s8 = "rfDesktopDirectory"
        $s9 = "TContextPopupEvent"
        $s10 = "Window Text"
        $s11 = "LoadStringA"
        $s12 = "TBrushStyle"
        $s13 = "GetWindowDC"
        $s14 = "TListColumn"
        $s15 = "Interval4YA"
        $s16 = "VarFileInfo"
        $s17 = "ProductName"
        $s18 = "Medium Gray"
        $s19 = "fsStayOnTop"
        $s20 = "TMenuMeasureItemEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 751KB and
    4 of them
}
    
