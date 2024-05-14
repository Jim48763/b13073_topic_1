rule acdeccdacefffbfeadeddb_exe {
strings:
        $s1 = "Error reading QCC marker"
        $s2 = "Cannot allocate memory"
        $s3 = "    Component %d: dc=%d ac=%d"
        $s4 = "invalid distance code"
        $s5 = "GetConsoleOutputCP"
        $s6 = "Invalid tile width"
        $s7 = "L217s<ih#\""
        $s8 = "/TF<)VGy#WH"
        $s9 = " cblkh=2^%d"
        $s10 = "packet body"
        $s11 = "`local vftable'"
        $s12 = "Unexpected OOM."
        $s13 = " Marker list: {"
        $s14 = "tiles require at least one resolution"
        $s15 = "TerminateProcess"
        $s16 = "SetFilePointerEx"
        $s17 = "Integer overflow"
        $s18 = "map/set too long"
        $s19 = "Zppm %u already read"
        $s20 = "_opj_read_header@12"
condition:
    uint16(0) == 0x5a4d and filesize < 1032KB and
    4 of them
}
    
