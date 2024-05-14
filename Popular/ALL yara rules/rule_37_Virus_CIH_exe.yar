rule Virus_CIH_exe {
strings:
        $s1 = "  Internet Address      Physical Address      Type"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "FileDescription"
        $s5 = "Microsoft Corporation"
        $s6 = "                with the Physical address eth_addr.  The Physical address is"
        $s7 = "0f2/33373;3?3C3G3K3O3S3\\7a7g7t7"
        $s8 = "FormatMessageA"
        $s9 = "_local_unwind2"
        $s10 = "  -s            Adds the host and associates the Internet address inet_addr"
        $s11 = "GetProcessHeap"
        $s12 = "CharToOemA"
        $s13 = "Copyright "
        $s14 = "_XcptFilter"
        $s15 = "KERNEL32.dll"
        $s16 = "inetmib1.dll"
        $s17 = "GetProcAddress"
        $s18 = "OriginalFilename"
        $s19 = "8:#:':+:/:3:7:;:?:C:G:K:O:S:W:[:_:c:g:k:o:"
        $s20 = "7 8&8,82888>8D8J8P8V8\\8b8h8D9J9P9V9"
condition:
    uint16(0) == 0x5a4d and filesize < 24KB and
    4 of them
}
    
