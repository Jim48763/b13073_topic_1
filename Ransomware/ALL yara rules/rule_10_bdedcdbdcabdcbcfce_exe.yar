rule bdedcdbdcabdcbcfce_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "FormatMessageW"
        $s3 = "CreateDIBitmap"
        $s4 = "GetTextMetricsW"
        $s5 = "KERNEL32.dll"
        $s6 = "=j&&LZ66lA??~"
        $s7 = "GetProcAddress"
        $s8 = ":7:=:H:Q:W:\\:b:&;O;^;v;"
        $s9 = "USER32.dll"
        $s10 = "CreateFontW"
        $s11 = "xxJo%%\\r..8$"
        $s12 = "GetTextColor"
        $s13 = "&Lj&6lZ6?~A?"
        $s14 = ".rdata$zzzdbg"
        $s15 = "SelectObject"
        $s16 = "GetMessageW"
        $s17 = ";';,;2;<;A;G;Q;V;\\;f;k;q;{;"
        $s18 = "566<6B6H6N6T6Z6`6f6l6r6x6~6"
        $s19 = "EndDialog"
        $s20 = "f\"\"D~**T"
condition:
    uint16(0) == 0x5a4d and filesize < 83KB and
    4 of them
}
    
