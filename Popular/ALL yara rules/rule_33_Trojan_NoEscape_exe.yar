rule Trojan_NoEscape_exe {
strings:
        $s1 = "ProductName"
        $s2 = "+hPg,96xuV{"
        $s3 = "Hgw|M8k)%rI"
        $s4 = "\"HS%G(k6|J"
        $s5 = "VarFileInfo"
        $s6 = "=8YMzOb!{F/"
        $s7 = "paEt2[k_,b4"
        $s8 = "FileDescription"
        $s9 = "GetModuleHandleA"
        $s10 = "38lju==g64,U"
        $s11 = "NETAPI32.dll"
        $s12 = "RtlGetVersion"
        $s13 = "    </security>"
        $s14 = "CoTaskMemFree"
        $s15 = "S\"{UkAntC"
        $s16 = "<SQ2aph%y/"
        $s17 = "a\"wN6WDpZ"
        $s18 = "09AZtvJ7)E"
        $s19 = "SOm^/(a'J-"
        $s20 = ":g<6tbh]2w"
condition:
    uint16(0) == 0x5a4d and filesize < 671KB and
    4 of them
}
    
