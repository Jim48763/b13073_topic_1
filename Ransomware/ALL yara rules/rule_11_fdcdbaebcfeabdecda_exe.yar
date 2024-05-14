rule fdcdbaebcfeabdecda_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "GetFileAttributesW"
        $s3 = "GetTextMetricsW"
        $s4 = "GetDlgItemTextW"
        $s5 = "KERNEL32.dll"
        $s6 = "GetKeyNameTextW"
        $s7 = "=j&&LZ66lA??~"
        $s8 = "GetProcAddress"
        $s9 = "GetDateFormatW"
        $s10 = "GetTextCharset"
        $s11 = "LoadImageW"
        $s12 = "k2U*6:v/*h"
        $s13 = "USER32.dll"
        $s14 = "xxJo%%\\r..8$"
        $s15 = "GetTextColor"
        $s16 = "&Lj&6lZ6?~A?"
        $s17 = "LoadLibraryW"
        $s18 = "GetAtomNameW"
        $s19 = ".rdata$zzzdbg"
        $s20 = "SetLastError"
condition:
    uint16(0) == 0x5a4d and filesize < 85KB and
    4 of them
}
    
