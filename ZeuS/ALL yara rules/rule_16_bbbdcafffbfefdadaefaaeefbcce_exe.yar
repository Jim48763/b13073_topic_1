rule bbbdcafffbfefdadaefaaeefbcce_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "FileDescription"
        $s4 = "GetModuleHandleA"
        $s5 = "PrivateBuild"
        $s6 = "WmnzY8WMa5|r"
        $s7 = "OpenFileMappingA"
        $s8 = "VirtualProtect"
        $s9 = "SizeofResource"
        $s10 = "LegalTrademarks"
        $s11 = "={e)(tPX<@"
        $s12 = "w?}'1B4ayr1"
        $s13 = "_XcptFilter"
        $s14 = "SpecialBuild"
        $s15 = "KERNEL32.dll"
        $s16 = "_adjust_fdiv"
        $s17 = "__getmainargs"
        $s18 = "OriginalFilename"
        $s19 = "H!fm_8q\"j\\"
        $s20 = "VirtualAlloc"
condition:
    uint16(0) == 0x5a4d and filesize < 209KB and
    4 of them
}
    
