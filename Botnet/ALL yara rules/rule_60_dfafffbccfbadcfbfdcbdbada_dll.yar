rule dfafffbccfbadcfbfdcbdbada_dll {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "Operation aborted"
        $s4 = "CoAddRefServerProcess"
        $s5 = "TInterfacedPersistent"
        $s6 = "'%s' is not a valid date"
        $s7 = "= =$=(=,=0=4=8=<=@=D=D>T>d>l>p>t>x>|>"
        $s8 = " 2001, 2002 Mike Lischke"
        $s9 = "TShortCutEvent"
        $s10 = "IScriptContext"
        $s11 = "TControlCanvas\\ZC"
        $s12 = "CoCreateInstanceEx"
        $s13 = "TContextPopupEvent"
        $s14 = "TStringsObj"
        $s15 = "GetWindowDC"
        $s16 = "Medium Gray"
        $s17 = "TGraphicXwB"
        $s18 = "TModulesObj"
        $s19 = "LoadStringA"
        $s20 = "MinValueXtF"
condition:
    uint16(0) == 0x5a4d and filesize < 971KB and
    4 of them
}
    
