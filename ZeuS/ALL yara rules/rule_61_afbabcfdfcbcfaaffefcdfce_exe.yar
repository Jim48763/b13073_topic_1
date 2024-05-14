rule afbabcfdfcbcfaaffefcdfce_exe {
strings:
        $s1 = " Nuke Yucca 2004-2009"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "oGetNumb9Fo<"
        $s6 = "VirtualProtect"
        $s7 = "TickCountN"
        $s8 = "NfoK4`@MH{"
        $s9 = "d$Sk%Gi*(o"
        $s10 = "EX\"~]pLIY"
        $s11 = "\"%Du-(=}C"
        $s12 = "gp{OpenThr@"
        $s13 = "ExitProcess"
        $s14 = "[>\\c_25u|T"
        $s15 = "GetProcAddress"
        $s16 = "OriginalFilename"
        $s17 = "VirtualAlloc"
        $s18 = "user32.dll"
        $s19 = "GetIfEntry"
        $s20 = "VS_VERSION_INFO"
condition:
    uint16(0) == 0x5a4d and filesize < 206KB and
    4 of them
}
    
