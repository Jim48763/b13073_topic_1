rule aecaeaebeeadcfaefabcfcbececfbfb_dll {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "Operation aborted"
        $s4 = "TPacketAttribute "
        $s5 = "CoAddRefServerProcess"
        $s6 = "EVariantBadVarTypeError"
        $s7 = "'%s' is not a valid date"
        $s8 = "TCustomActionControl"
        $s9 = " 2001, 2002 Mike Lischke"
        $s10 = "Database Login"
        $s11 = "TShortCutEvent"
        $s12 = "HintShortCutsT"
        $s13 = "OnUpdateErrorH"
        $s14 = "TMSDOMNamedNodeMap"
        $s15 = "CoCreateInstanceEx"
        $s16 = "BeforeDisconnect\\"
        $s17 = "TContextPopupEvent"
        $s18 = "GetWindowDC"
        $s19 = "Medium Gray"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 1051KB and
    4 of them
}
    
