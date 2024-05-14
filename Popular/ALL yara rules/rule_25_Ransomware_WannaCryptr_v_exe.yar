rule Ransomware_WannaCryptr_v_exe {
strings:
        $s1 = "cmd.exe /c \"%s\""
        $s2 = "__CxxFrameHandler"
        $s3 = "            processorArchitecture=\"*\""
        $s4 = "RegSetValueExA"
        $s5 = "invalid distance code"
        $s6 = "xLjDJa'SHvZ"
        $s7 = "XyS\"'wK@Y="
        $s8 = "CUip0,Yes8v"
        $s9 = "|HDA$5.*r/j"
        $s10 = "ma\"3`&BF#W"
        $s11 = "}9zf]A\"g 0"
        $s12 = "VarFileInfo"
        $s13 = "dQe`5yO_$%;"
        $s14 = "ProductName"
        $s15 = "S*91q$4\"FD"
        $s16 = "BqZ=(JjQ:cS"
        $s17 = "fg|tLRKVj`Q"
        $s18 = "]p,-WTj6Bg("
        $s19 = "*d19_Zxp(Js"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 3437KB and
    4 of them
}
    
