rule dcadecedecaaabdfccfd_exe {
strings:
        $s1 = "EVariantBadVarTypeError"
        $s2 = "'%s' is not a valid date"
        $s3 = "SetWindowTheme"
        $s4 = "RegSetValueExA"
        $s5 = "OnMouseWheelUp"
        $s6 = "TWinControlActionLink"
        $s7 = "TContextPopupEvent"
        $s8 = "TPrintScale"
        $s9 = "Medium Gray"
        $s10 = "TDragObject"
        $s11 = "TBrushStyle"
        $s12 = "GroupIndex$"
        $s13 = "fsStayOnTop"
        $s14 = "LoadStringA"
        $s15 = "OnDrawItem("
        $s16 = "clBtnShadow"
        $s17 = "Window Text"
        $s18 = "GetWindowDC"
        $s19 = "TMenuMeasureItemEvent"
        $s20 = "GetKeyboardType"
condition:
    uint16(0) == 0x5a4d and filesize < 481KB and
    4 of them
}
    
