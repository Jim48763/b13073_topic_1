rule eefecacfcdbbaeddbbebfebdb_exe {
strings:
        $s1 = "ProductName"
        $s2 = "xUAE@XZ?e7s"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "zlhmr];mcpX)"
        $s6 = "OLEAUT32.dll"
        $s7 = "PrivateBuild"
        $s8 = "FFormazBaguMZ"
        $s9 = "InstallShield"
        $s10 = "VirtualProtect"
        $s11 = "T * FROM cc'VO5"
        $s12 = "LegalTrademarks"
        $s13 = "ExitProcess"
        $s14 = "baiduConnec"
        $s15 = "SpecialBuild"
        $s16 = "GetProcAddress"
        $s17 = "OriginalFilename"
        $s18 = "y(,0222248<@2222DHLP"
        $s19 = "MSVCRT.dll"
        $s20 = "GetModuleH"
condition:
    uint16(0) == 0x5a4d and filesize < 73KB and
    4 of them
}
    
