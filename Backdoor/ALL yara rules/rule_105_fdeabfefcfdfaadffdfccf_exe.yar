rule fdeabfefcfdfaadffdfccf_exe {
strings:
        $s1 = "&v!Vj!g!rAti{M"
        $s2 = "?BFSROP21h,"
        $s3 = "?D (\"zKiZb"
        $s4 = "GTlcX;-w`Wg"
        $s5 = "ed memoryZak has "
        $s6 = "-%%?.bieD\"+"
        $s7 = "3%s,:gID: \""
        $s8 = "v0(d`'^,Uy(H"
        $s9 = "TModuleInfoy"
        $s10 = "NetShareEnum"
        $s11 = "KeySlot/Auth"
        $s12 = "#X'/MtkEXr$C"
        $s13 = "NetAPI32.dll"
        $s14 = "`\\7Rjei`[]2f"
        $s15 = "k<il_urlouz&B"
        $s16 = "WNetOpenEnumA"
        $s17 = "CryptUnprotectData"
        $s18 = "SOFTWARE\\{\\De"
        $s19 = "|x9999tplh9999d`\\X9999TPLH9999D@<8999940,(9999$ "
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 367KB and
    4 of them
}
    
