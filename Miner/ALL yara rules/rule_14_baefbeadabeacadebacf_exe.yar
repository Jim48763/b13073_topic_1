rule baefbeadabeacadebacf_exe {
strings:
        $s1 = "ProductName"
        $s2 = "<XBeg4 HWND"
        $s3 = "(/clr)=Rpia"
        $s4 = "/0123^89:;<"
        $s5 = "&Na!mT9vF$'"
        $s6 = "VarFileInfo"
        $s7 = " LoadSE(%u)"
        $s8 = "R\"ZXYZ[\\]^_`a"
        $s9 = "FileDescription"
        $s10 = "Microsoft Corporation"
        $s11 = "OLEAUT32.dll"
        $s12 = "WINSPOOL.DRV"
        $s13 = "?Pai\\PBcQ`s/?"
        $s14 = "VirtualProtect"
        $s15 = "PathIsUNCA"
        $s16 = "'tFa[hSbMX"
        $s17 = "08X (nIDC="
        $s18 = "v2/Qual4!W"
        $s19 = ">4`1[i9^7y"
        $s20 = "Ovw-6VQKsb"
condition:
    uint16(0) == 0x5a4d and filesize < 260KB and
    4 of them
}
    
