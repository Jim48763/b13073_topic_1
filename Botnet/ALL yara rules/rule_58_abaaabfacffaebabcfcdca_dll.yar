rule abaaabfacffaebabcfcdca_dll {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "IDOMNamedNodeMapl"
        $s4 = "CoAddRefServerProcess"
        $s5 = "EVariantBadVarTypeError"
        $s6 = " 2001, 2002 Mike Lischke"
        $s7 = "Database Login"
        $s8 = "TShortCutEvent"
        $s9 = "TChartArrowPen"
        $s10 = "CoCreateInstanceEx"
        $s11 = "TGradientDirection"
        $s12 = "TContextPopupEvent"
        $s13 = "qP3aWbwej<4"
        $s14 = "GetWindowDC"
        $s15 = "(fgEPAi~VN_"
        $s16 = "Medium Gray"
        $s17 = ";l^z7wUy6tW"
        $s18 = "Interval({A"
        $s19 = ";kcX53JP(Ws"
        $s20 = "K7LMYeV|gsy"
condition:
    uint16(0) == 0x5a4d and filesize < 870KB and
    4 of them
}
    
