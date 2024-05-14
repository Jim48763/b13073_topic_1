rule dcbdfebafbefbeaaefedcfa_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TInterfacedPersistent"
        $s3 = "CoAddRefServerProcess"
        $s4 = "TCustomControlAction"
        $s5 = "ImmSetCompositionFontA"
        $s6 = "GetEnhMetaFilePaletteEntries"
        $s7 = "clWebLightSteelBlue"
        $s8 = "Directory not empty"
        $s9 = " 2001, 2002 Mike Lischke"
        $s10 = ":p=w=~=P>`>P?U?d?i?x?}?"
        $s11 = "TIdStatusEvent"
        $s12 = "CoInitializeEx"
        $s13 = "SetWindowTheme"
        $s14 = "ckRunningOrNew"
        $s15 = "clWebPaleVioletRed"
        $s16 = "EIdUnknownProtocol"
        $s17 = "TContextPopupEvent"
        $s18 = "Windows-31J"
        $s19 = "WSAJoinLeaf"
        $s20 = "fsStayOnTop"
condition:
    uint16(0) == 0x5a4d and filesize < 698KB and
    4 of them
}
    