rule bffaacadacfcabcceea_exe {
strings:
        $s1 = "MetadataReferenceProperties"
        $s2 = "ConditionalAttribute"
        $s3 = "XamlGeneratedNamespace"
        $s4 = "get_ObjectFormatter"
        $s5 = "set_PlacementTarget"
        $s6 = "GetLastWriteTimeUtc"
        $s7 = "set_IsParallelEntry"
        $s8 = "millisecondsTimeout"
        $s9 = "RuntimeHelpers"
        $s10 = "RelativeSource"
        $s11 = "StringComparer"
        $s12 = "get_IsCanceled"
        $s13 = "'$$method0x6000003-1'"
        $s14 = "set_CustomCategory"
        $s15 = "RuntimeFieldHandle"
        $s16 = "STAThreadAttribute"
        $s17 = "#\"&5'74632"
        $s18 = "+f$H^XbVS!r"
        $s19 = "W=#uY2BrUI1"
        $s20 = "tumblr_sign"
condition:
    uint16(0) == 0x5a4d and filesize < 1250KB and
    4 of them
}
    
