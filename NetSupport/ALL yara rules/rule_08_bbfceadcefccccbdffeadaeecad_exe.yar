rule bbfceadcefccccbdffeadaeecad_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "NetSupport Ltd1"
        $s4 = "FileDescription"
        $s5 = "GetModuleHandleW"
        $s6 = "PrivateBuild"
        $s7 = "    </security>"
        $s8 = "Greater Manchester1"
        $s9 = "LegalTrademarks"
        $s10 = "ExitProcess"
        $s11 = "</assembly>"
        $s12 = "KERNEL32.dll"
        $s13 = "SpecialBuild"
        $s14 = "Jersey City1"
        $s15 = "Peterborough1"
        $s16 = "OriginalFilename"
        $s17 = "client32.exe"
        $s18 = "VS_VERSION_INFO"
        $s19 = "Translation"
        $s20 = "CompanyName"
condition:
    uint16(0) == 0x5a4d and filesize < 114KB and
    4 of them
}
    
