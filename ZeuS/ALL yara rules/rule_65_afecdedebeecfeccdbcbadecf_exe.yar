rule afecdedebeecfeccdbcbadecf_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "}2c|OX-scKMF"
        $s3 = "*R\\{,`)z7nd"
        $s4 = "SHAutoComplete"
        $s5 = "RegOpenKeyExA"
        $s6 = "v)q;w kXJS"
        $s7 = "^X]%ySkW?b"
        $s8 = "_EFcodpbHg"
        $s9 = "H&^.C8DFT("
        $s10 = "Qwu[B5kst9s"
        $s11 = "version.dll"
        $s12 = "GetProcAddress"
        $s13 = "CoInitialize"
        $s14 = "\\0Itv5.,D"
        $s15 = "lyjQDITDf;"
        $s16 = "TranslateMessage"
        $s17 = "advapi32.dll"
        $s18 = "LoadLibraryA"
        $s19 = "shlwapi.dll"
        $s20 = "comctl32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 364KB and
    4 of them
}
    
