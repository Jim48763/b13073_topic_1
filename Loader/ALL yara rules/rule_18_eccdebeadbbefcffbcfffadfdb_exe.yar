rule eccdebeadbbefcffbcfffadfdb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "msctls_progress32"
        $s3 = "TInterfacedPersistent"
        $s4 = "EVariantBadVarTypeError"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "<I@88@8HD>PK=J@<7?8"
        $s7 = "clWebLightSteelBlue"
        $s8 = "TActionClientsClass"
        $s9 = " 2001, 2002 Mike Lischke"
        $s10 = "=*>@>V>l>P?T?X?\\?`?d?h?l?p?t?x?|?"
        $s11 = "TComboBoxStyle"
        $s12 = "SetWindowTheme"
        $s13 = "HintShortCutsT"
        $s14 = "CoInitializeEx"
        $s15 = "clWebOrangeRed"
        $s16 = "ckRunningOrNew"
        $s17 = "LinkedActionLists("
        $s18 = "TContextPopupEvent"
        $s19 = "CoCreateInstanceEx"
        $s20 = "QueryServiceStatus"
condition:
    uint16(0) == 0x5a4d and filesize < 1065KB and
    4 of them
}
    
