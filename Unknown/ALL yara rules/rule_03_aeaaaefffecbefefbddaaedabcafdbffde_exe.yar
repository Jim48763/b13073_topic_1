rule aeaaaefffecbefefbddaaedabcafdbffde_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "VirtualAllocEx"
        $s3 = "RegSetValueExA"
        $s4 = "In-rmBHio%4"
        $s5 = "7Us>B-A|Fnt"
        $s6 = "GetEnhMetaFileW"
        $s7 = "GetModuleHandleA"
        $s8 = "TDen#Boc>CsT"
        $s9 = "SysListView32"
        $s10 = ".Lo0MlA7@occ-"
        $s11 = "Greater Manchester1"
        $s12 = "ImmSetOpenStatus"
        $s13 = "cr4Aof/,ke"
        $s14 = "Th:E pqYgr"
        $s15 = ":0ls&Bca.o"
        $s16 = "eaoIEv~>tA"
        $s17 = "_XcptFilter"
        $s18 = "RichEdit20A"
        $s19 = "KERNEL32.dll"
        $s20 = "ADVAPI32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 878KB and
    4 of them
}
    
