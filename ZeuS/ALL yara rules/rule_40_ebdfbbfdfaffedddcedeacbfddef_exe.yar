rule ebdfbbfdfaffedddcedeacbfddef_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "?#C[o_*^gqH"
        $s4 = "FileDescription"
        $s5 = "COMDLG32.dll"
        $s6 = "OLEAUT32.dll"
        $s7 = "BringWindowToTop"
        $s8 = "TLM)Ke*~-G"
        $s9 = "PECompact2"
        $s10 = "T]v;R4R|8h4o"
        $s11 = "ADVAPI32.dll"
        $s12 = "GetProcAddress"
        $s13 = "OriginalFilename"
        $s14 = "VirtualAlloc"
        $s15 = "!)Yj.<*\"j"
        $s16 = "s&AZ`\"!sO"
        $s17 = "USER32.dll"
        $s18 = "VS_VERSION_INFO"
        $s19 = "CompanyName"
        $s20 = "Translation"
condition:
    uint16(0) == 0x5a4d and filesize < 208KB and
    4 of them
}
    
