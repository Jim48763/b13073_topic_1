rule daccddbddefceecceecacdeadccaec_exe {
strings:
        $s1 = "ttdSecondaryPanel"
        $s2 = "TRttiClassRefType"
        $s3 = "Fisc_dsql_prepare"
        $s4 = "TThemedDatePicker"
        $s5 = "procedure NewPage"
        $s6 = "FAlignControlList"
        $s7 = "EndFunctionInvoke"
        $s8 = "claMediumseagreen"
        $s9 = "Operation aborted"
        $s10 = "GlassHatchCBClick"
        $s11 = "msctls_progress32"
        $s12 = "TRttiManagedField"
        $s13 = "VerticalAlignment"
        $s14 = "RollbackRetaining"
        $s15 = "FCalcFieldsOffset"
        $s16 = "msctls_trackbar32"
        $s17 = "TfrxDesignerUnits"
        $s18 = "FCaptionEmulation"
        $s19 = "blob_desc_charset"
        $s20 = "FCreatingMainForm"
condition:
    uint16(0) == 0x5a4d and filesize < 5397KB and
    4 of them
}
    
