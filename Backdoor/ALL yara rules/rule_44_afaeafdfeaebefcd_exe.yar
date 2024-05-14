rule afaeafdfeaebefcd_exe {
strings:
        $s1 = "ProductName"
        $s2 = ".-kX+E*P>_("
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "Microsoft Corp."
        $s6 = "netapi32.dll"
        $s7 = "VirtualProtect"
        $s8 = "Ab<XHSOh3B"
        $s9 = "ExitProcess"
        $s10 = "PACKAGEINFO"
        $s11 = "IsEqualGUID"
        $s12 = "\\}Snu>O+^J"
        $s13 = "-di\\RC'4% "
        $s14 = "version.dll"
        $s15 = "&hbZ!!Ou\"p"
        $s16 = "6O1%uOE'C0/"
        $s17 = "VariantCopy"
        $s18 = "AVICAP32.DLL"
        $s19 = "GetProcAddress"
        $s20 = "OriginalFilename"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    
