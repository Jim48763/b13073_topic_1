rule ebefaccdcdeceefadceccdbe_exe {
strings:
        $s1 = "6 6$6(6,6064686<6@6D6H6L6P6T6 7$7(7,7074787<7@7D7H7L7P7T7l7x7|7"
        $s2 = "TPacketAttribute "
        $s3 = "clInactiveCaption"
        $s4 = "TInterfacedPersistent"
        $s5 = "CoAddRefServerProcess"
        $s6 = "\\DATABASES\\%s\\DB INFO"
        $s7 = "'%s' is not a valid date"
        $s8 = "\\DRIVERS\\%s\\DB OPEN"
        $s9 = "GetEnhMetaFilePaletteEntries"
        $s10 = "TShortCutEvent"
        $s11 = "TFileStreamDeA"
        $s12 = "Database Login"
        $s13 = "OnMouseWheelUp"
        $s14 = "RequestLive<bA"
        $s15 = "CoCreateInstanceEx"
        $s16 = "EExternalException"
        $s17 = "TContextPopupEvent"
        $s18 = "TBlobStream"
        $s19 = "TPrintScale"
        $s20 = "clBtnShadow"
condition:
    uint16(0) == 0x5a4d and filesize < 1033KB and
    4 of them
}
    
