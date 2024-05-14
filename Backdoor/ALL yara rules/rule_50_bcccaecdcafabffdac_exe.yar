rule bcccaecdcafabffdac_exe {
strings:
        $s1 = "CMTSilent=1"
        $s2 = "nPv`~pCOL|>"
        $s3 = "GETPASSWORD1"
        $s4 = "ebuggn%WhV`0"
        $s5 = ".LW'efaul5ie"
        $s6 = "LockExclusiv"
        $s7 = "sG@vDT\"Uv`F"
        $s8 = "</trustInfo>"
        $s9 = "bk5bxKVnY/Zx-"
        $s10 = "_hypotN@or?y0"
        $s11 = "      language=\"*\"/>"
        $s12 = ".ryptProtectMemo"
        $s13 = "VirtualProtect"
        $s14 = "190725141838Z0#"
        $s15 = "PPW@h<WU<dgnqx<"
        $s16 = "`[o?Gr)I5l"
        $s17 = "49@:L;X>#G"
        $s18 = "~L(z*d.Se9"
        $s19 = "2bfF=}Z!\""
        $s20 = "|C>r<T'(o]"
condition:
    uint16(0) == 0x5a4d and filesize < 656KB and
    4 of them
}
    
