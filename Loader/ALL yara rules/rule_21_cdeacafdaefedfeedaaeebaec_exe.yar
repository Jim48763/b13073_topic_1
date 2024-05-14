rule cdeacafdaefedfeedaaeebaec_exe {
strings:
        $s1 = "$%&PUQPWQJKLJLLVTSQQU"
        $s2 = "TInterfacedPersistent"
        $s3 = "SetWindowTheme"
        $s4 = "'$'ZY^QSTSTSTUWPWPURR"
        $s5 = "TContextPopupEvent"
        $s6 = "MHJSPTQTVPRSPUQ(/("
        $s7 = "QueryServiceStatus"
        $s8 = "TPrintScale"
        $s9 = "Medium Gray"
        $s10 = "TDragObject"
        $s11 = "Read Async!"
        $s12 = "TBrushStyle"
        $s13 = "fsStayOnTop"
        $s14 = "LoadStringA"
        $s15 = "clBtnShadow"
        $s16 = "Window Text"
        $s17 = "GetWindowDC"
        $s18 = "TMenuMeasureItemEvent"
        $s19 = "GetKeyboardType"
        $s20 = "IsWindowVisible"
condition:
    uint16(0) == 0x5a4d and filesize < 837KB and
    4 of them
}
    
