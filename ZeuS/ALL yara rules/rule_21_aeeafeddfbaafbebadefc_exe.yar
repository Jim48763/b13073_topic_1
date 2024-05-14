rule aeeafeddfbaafbebadefc_exe {
strings:
        $s1 = "EVariantBadIndexError"
        $s2 = "PrintDlgExW"
        $s3 = "LoadStringA"
        $s4 = "0123456789|"
        $s5 = "GetKeyboardType"
        $s6 = "GetThreadLocale"
        $s7 = "TResourceManager"
        $s8 = "GetModuleHandleA"
        $s9 = "GetSystemPaletteEntries"
        $s10 = "GetCurrentThreadId"
        $s11 = "GetLocalTime"
        $s12 = "EInvalidCast"
        $s13 = "TFontCharset"
        $s14 = "EOutOfMemory"
        $s15 = "FPUMaskValue"
        $s16 = "cl3DDkShadow"
        $s17 = "clBackground"
        $s18 = "TThreadList|"
        $s19 = "JOHAB_CHARSET"
        $s20 = "FormatMessageA"
condition:
    uint16(0) == 0x5a4d and filesize < 234KB and
    4 of them
}
    
