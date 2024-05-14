rule dadefdcfdfcadeaaeaabbbcbadae_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "TStringSparseList"
        $s5 = "OnItemSelected,?H"
        $s6 = "OnCustomizeAddedd"
        $s7 = "TPacketAttribute "
        $s8 = "Possible deadlock"
        $s9 = "CoAddRefServerProcess"
        $s10 = "GetEnvironmentStrings"
        $s11 = "EVariantBadVarTypeError"
        $s12 = "8 8$8(8,8084888<8@8D8H8L8P8T8X8\\8`8d8h8l8p8$6(6,6064686P6f6j6"
        $s13 = "Unable to insert an item"
        $s14 = "'%s' is not a valid date"
        $s15 = "=X?\\?`?d?h?l?p?H9L9P9T9X9l9p9t9x9|9"
        $s16 = "File already exists"
        $s17 = "Invalid access code"
        $s18 = "Directory not empty"
        $s19 = "Database Login"
        $s20 = "TShortCutEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 1224KB and
    4 of them
}
    
