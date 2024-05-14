rule Trojan_BossDaMajor_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "P-v2edecompile"
        $s3 = "My.WebServices"
        $s4 = "v2eprogrampathname"
        $s5 = "AuthenticationMode"
        $s6 = "STAThreadAttribute"
        $s7 = "DesignerGeneratedAttribute"
        $s8 = "%LU\")ArItP"
        $s9 = "My.Computer"
        $s10 = "\"X~i])8'xD"
        $s11 = "DV{lh4w9XYM"
        $s12 = "v\"pEX(m4fJ"
        $s13 = "xi#M\"hq7o`"
        $s14 = "PB_WindowID"
        $s15 = "VarFileInfo"
        $s16 = "/?W~_7qs%fb"
        $s17 = "ProductName"
        $s18 = "_CorExeMain"
        $s19 = "=sBv&?H>1%C"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 1972KB and
    4 of them
}
    
