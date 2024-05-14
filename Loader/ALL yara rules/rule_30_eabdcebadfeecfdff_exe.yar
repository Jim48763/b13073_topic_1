rule eabdcebadfeecfdff_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "msctls_trackbar32"
        $s3 = "TMeasureItemEvent"
        $s4 = "Possible deadlock"
        $s5 = "TPacketAttribute "
        $s6 = "msctls_progress32"
        $s7 = "TCustomStaticText"
        $s8 = "GetEnvironmentStrings"
        $s9 = "TSeriesMarksPositions"
        $s10 = "TInterfacedPersistent"
        $s11 = "EUnsupportedTypeError"
        $s12 = "8 8$8(8,8084888<8@8D8H8L8P8T8 4$4(4,4044484<4@4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|4"
        $s13 = "Unable to insert an item"
        $s14 = "\\DATABASES\\%s\\DB INFO"
        $s15 = "'%s' is not a valid date"
        $s16 = "< <,<@<H<L<P<T<X<\\<`<d<h<X8\\8`8d8h8l8p8t8x8|8"
        $s17 = "= =$;(;,;0;4;8;<;@;D;H;L;P;T;X;\\;`;d;h;l;p;t;x;|;"
        $s18 = "5\"5(5.545:5@5D2J2P2V2\\2b2h2n2t2z2"
        $s19 = "\\DRIVERS\\%s\\DB OPEN"
        $s20 = "GetEnhMetaFilePaletteEntries"
condition:
    uint16(0) == 0x5a4d and filesize < 1488KB and
    4 of them
}
    
