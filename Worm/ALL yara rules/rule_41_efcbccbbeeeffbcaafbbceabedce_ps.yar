rule efcbccbbeeeffbcaafbbceabedce_ps {
strings:
        $s1 = "while($true)"
        $s2 = "Function INF {"
        $s3 = "    return $Response"
        $s4 = "DropToStartup"
        $s5 = "    } catch { }"
        $s6 = "        break }"
        $s7 = "        'TR' {"
        $s8 = "break }"
        $s9 = "'Un' {"
        $s10 = "    try"
        $s11 = "    }"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
