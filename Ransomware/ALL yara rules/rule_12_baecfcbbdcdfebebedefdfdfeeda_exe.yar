rule baecfcbbdcdfebebedefdfdfeeda_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "GetTickCount"
        $s3 = "GetWindowTextW"
        $s4 = "FormatMessageW"
        $s5 = "KERNEL32.dll"
        $s6 = "GetKeyNameTextW"
        $s7 = "=j&&LZ66lA??~"
        $s8 = "GetProcAddress"
        $s9 = "GetDateFormatW"
        $s10 = "LoadImageW"
        $s11 = "USER32.dll"
        $s12 = "xxJo%%\\r..8$"
        $s13 = "&Lj&6lZ6?~A?"
        $s14 = "LoadLibraryW"
        $s15 = "SetTextColor"
        $s16 = ".rdata$zzzdbg"
        $s17 = "GetLastError"
        $s18 = "GetDlgItem"
        $s19 = "SelectObject"
        $s20 = "CreateMenu"
condition:
    uint16(0) == 0x5a4d and filesize < 100KB and
    4 of them
}
    
