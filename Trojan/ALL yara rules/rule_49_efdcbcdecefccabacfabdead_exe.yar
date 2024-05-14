rule efdcbcdecefccabacfabdead_exe {
strings:
        $s1 = "%8lF$TDz9 7"
        $s2 = "G>_V`d<)bw'"
        $s3 = ",-mzEDSCF$^"
        $s4 = "-sNAg<\":*f"
        $s5 = "l=?1h\"{EA_"
        $s6 = "GcJPez0-Wf;"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "PYnr\"V+1_]"
        $s10 = "!KW[^|<{RPx"
        $s11 = "aSr.OkHh^*;"
        $s12 = "f\"&g)}WAQa"
        $s13 = "7\"oHUg&<A/"
        $s14 = ":O Hjp#)D*J"
        $s15 = "wqhBC:t(<Pu"
        $s16 = "y,v:xBtf).w"
        $s17 = "FHwa) \"r@g"
        $s18 = "5F[]P}!'c<7"
        $s19 = "0lYk(#xg>Q6"
        $s20 = "T24$XCa c}z"
condition:
    uint16(0) == 0x5a4d and filesize < 9384KB and
    4 of them
}
    
