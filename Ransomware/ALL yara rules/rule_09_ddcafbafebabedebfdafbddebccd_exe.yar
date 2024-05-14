rule ddcafbafebabedebfdafbddebccd_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "8(8:8@8J8P8b8h8r8;9M9S9]9c9u9{9"
        $s3 = "FormatMessageW"
        $s4 = "GetFileAttributesW"
        $s5 = "GetDeviceCaps"
        $s6 = "GetDlgItemTextW"
        $s7 = "KERNEL32.dll"
        $s8 = "GetClassNameW"
        $s9 = "=j&&LZ66lA??~"
        $s10 = "GetTextCharset"
        $s11 = "LoadImageW"
        $s12 = "USER32.dll"
        $s13 = "CreateFontW"
        $s14 = "xxJo%%\\r..8$"
        $s15 = "&Lj&6lZ6?~A?"
        $s16 = "GetAtomNameW"
        $s17 = "555O5X5\"656?6,7?7`7v7"
        $s18 = ".rdata$zzzdbg"
        $s19 = "SetLastError"
        $s20 = "GetDlgItem"
condition:
    uint16(0) == 0x5a4d and filesize < 72KB and
    4 of them
}
    
