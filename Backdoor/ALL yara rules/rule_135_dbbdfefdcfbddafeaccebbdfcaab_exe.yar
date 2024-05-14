rule dbbdfefdcfbddafeaccebbdfcaab_exe {
strings:
        $s1 = "ttdSecondaryPanel"
        $s2 = "DefOrientation$D@"
        $s3 = "TRttiClassRefType"
        $s4 = "TThemedDatePicker"
        $s5 = "procedure NewPage"
        $s6 = "FAlignControlList"
        $s7 = "/Filter /Standard"
        $s8 = "EndFunctionInvoke"
        $s9 = "claMediumseagreen"
        $s10 = "Operation aborted"
        $s11 = "horizontal_header"
        $s12 = "GlassHatchCBClick"
        $s13 = "msctls_progress32"
        $s14 = "/Macrosheet /Part"
        $s15 = "VerticalAlignment"
        $s16 = "RollbackRetaining"
        $s17 = "msctls_trackbar32"
        $s18 = "System.ClassesTvI"
        $s19 = "TfrxDesignerUnits"
        $s20 = "FCaptionEmulation"
condition:
    uint16(0) == 0x5a4d and filesize < 5927KB and
    4 of them
}
    
