rule aebfbfffcdcbfdedaddbddb_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "cross device link"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = "_libm_sse2_pow_precise"
        $s7 = "executable format error"
        $s8 = "SeProfileSingleProcessPrivilege"
        $s9 = "result out of range"
        $s10 = "directory not empty"
        $s11 = "VirtualAllocEx"
        $s12 = "DividerOpacity"
        $s13 = "offsize >= 1 && offsize <= 4"
        $s14 = "width <= 0xffff && height <= 0xffff"
        $s15 = "invalid string position"
        $s16 = "ios_base::failbit set"
        $s17 = "operation canceled"
        $s18 = "Sr2t\"=U4k~"
        $s19 = "i!&#AY6HoT<"
        $s20 = "LC_MONETARY"
condition:
    uint16(0) == 0x5a4d and filesize < 731KB and
    4 of them
}
    
