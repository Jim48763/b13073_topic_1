rule dceffecbfcafdbdacdcadefff_dll {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "EVariantDispatchError"
        $s3 = "TInterfacedPersistent"
        $s4 = "EVariantBadVarTypeError"
        $s5 = "ImmSetCompositionFontA"
        $s6 = " 2001, 2002 Mike Lischke"
        $s7 = "OnMouseWheelUp"
        $s8 = "AytZxl|xdo{xX "
        $s9 = "GetWindowTheme"
        $s10 = "TWinControlActionLink"
        $s11 = "EExternalException"
        $s12 = "TContextPopupEvent"
        $s13 = "?O2m]DIn={o"
        $s14 = "<7QeqYjg[> "
        $s15 = "dfl~YtO{giE"
        $s16 = "JWAgL5Htc_a"
        $s17 = "9/dgH56wazx"
        $s18 = "$C|q/Me^au["
        $s19 = "GetWindowDC"
        $s20 = ">6wSvFiChds"
condition:
    uint16(0) == 0x5a4d and filesize < 680KB and
    4 of them
}
    
