rule ceeaeabacebdaabdbba_dll {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "Operation aborted"
        $s3 = "TPacketAttribute "
        $s4 = "EVariantDispatchError"
        $s5 = "TInterfacedPersistent"
        $s6 = "\\DATABASES\\%s\\DB INFO"
        $s7 = "\\DRIVERS\\%s\\DB OPEN"
        $s8 = "ImmSetCompositionFontA"
        $s9 = "GetEnhMetaFilePaletteEntries"
        $s10 = " 2001, 2002 Mike Lischke"
        $s11 = "TChartArrowPen"
        $s12 = "GetWindowTheme"
        $s13 = "TWinControlActionLink"
        $s14 = "TAddTeeFunctionTtH"
        $s15 = "CoCreateInstanceEx"
        $s16 = "EExternalException"
        $s17 = "TSQLTimeStampData("
        $s18 = "TContextPopupEvent"
        $s19 = "TGradientDirection"
        $s20 = "TBlobStream"
condition:
    uint16(0) == 0x5a4d and filesize < 883KB and
    4 of them
}
    
