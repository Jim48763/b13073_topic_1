rule abacccefaecfdeabccdfded_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "H(coB!np6Ov"
        $s5 = "FileDescription"
        $s6 = "GetModuleHandleA"
        $s7 = "Greater Manchester1"
        $s8 = "l&(xpLCw|J"
        $s9 = "y1{R\"*G<:"
        $s10 = "ur5Fj}LI{V"
        $s11 = "ufMgWHybLv"
        $s12 = "B0x_P&ro@C"
        $s13 = "$BHp(7qL<M"
        $s14 = "KERNEL32.dll"
        $s15 = "ADVAPI32.dll"
        $s16 = "Jersey City1"
        $s17 = "GetProcAddress"
        $s18 = "OriginalFilename"
        $s19 = "Classic Shell"
        $s20 = "GetTextCharset"
condition:
    uint16(0) == 0x5a4d and filesize < 230KB and
    4 of them
}
    
