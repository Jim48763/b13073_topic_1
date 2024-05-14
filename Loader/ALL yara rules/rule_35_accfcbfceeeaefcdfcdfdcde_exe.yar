rule accfcbfceeeaefcdfcdfdcde_exe {
strings:
        $s1 = "{|raaKDD/11-./zrg"
        $s2 = "}}}{{{{{{xxxxxxtttrrrpppmmmkkkjjjffffffiiiiiimmmyyy"
        $s3 = "EVariantBadVarTypeError"
        $s4 = "30314743774a5c2b2041456303013126475c240b4276265c5e62221a33295c58200b1b0101525920030a302251572e330722161c76270b1922"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "TActionClientsClass"
        $s7 = "SetWindowTheme"
        $s8 = "HintShortCuts<"
        $s9 = "CoInitializeEx"
        $s10 = "TContextPopupEvent"
        $s11 = "CoCreateInstanceEx"
        $s12 = "TPrintScale"
        $s13 = "Medium Gray"
        $s14 = "TDragObject"
        $s15 = "OnUpdate|hA"
        $s16 = "TPicture ?B"
        $s17 = "Interval|hA"
        $s18 = "TBrushStyle"
        $s19 = "MaxWidthH{C"
        $s20 = "fsStayOnTop"
condition:
    uint16(0) == 0x5a4d and filesize < 713KB and
    4 of them
}
    
