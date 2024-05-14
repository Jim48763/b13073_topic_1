rule fcfbeaeebdaedaabfeebdafffcbb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "4`2UUCVWDVcgVcAc`TVdd"
        $s5 = "6GRcZR_e3RUGRcEjaV6cc`c"
        $s6 = "{~upujci^Ti^Ti^T_VMTMETMETME!"
        $s7 = "xsxngpe\\i^TTMETMETME!"
        $s8 = "le\\_XP^WN]VM^WN_XPle\\"
        $s9 = "yqzmbwk`wk`wk`]TKTMETMETME"
        $s10 = "If-Unmodified-Since"
        $s11 = "Yeead+  UZdT`cUT`^ "
        $s12 = "4`:_ZeZR]ZkV6i"
        $s13 = "TShortCutEvent"
        $s14 = "EDB=EZ^VDeR^a5ReR|"
        $s15 = "TContextPopupEvent"
        $s16 = "4`4cVReV:_deR_TV6i"
        $s17 = "GetWindowDC"
        $s18 = "TStrings, A"
        $s19 = "Medium Gray"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 1392KB and
    4 of them
}
    
