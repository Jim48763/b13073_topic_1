rule edfbaadebfffefbbbedafdcddf_exe {
strings:
        $s1 = "</trustInfo>             </assembly>"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "5\"-j6N.eBL"
        $s5 = "hQM&8Z-pT7("
        $s6 = "kh#1-Fi~S;N"
        $s7 = "FileDescription"
        $s8 = "Tiled Tends Sifts"
        $s9 = "VirtualProtect"
        $s10 = "<security>"
        $s11 = "L7%N@1E ,-"
        $s12 = "DpI&Ptv$\\T"
        $s13 = "ExitProcess"
        $s14 = "           <requestedPrivileges>"
        $s15 = "GetProcAddress"
        $s16 = "OriginalFilename"
        $s17 = "VirtualAlloc"
        $s18 = "</security>      "
        $s19 = "Zoo Toby Logs Mop"
        $s20 = "p\"*I$$VL."
condition:
    uint16(0) == 0x5a4d and filesize < 258KB and
    4 of them
}
    
