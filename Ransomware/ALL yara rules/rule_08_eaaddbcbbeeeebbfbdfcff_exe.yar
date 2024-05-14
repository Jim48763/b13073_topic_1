rule eaaddbcbbeeeebbfbdfcff_exe {
strings:
        $s1 = "actualUnderlength"
        $s2 = "duplicate field `"
        $s3 = "floating point `4"
        $s4 = "fatal runtime error: "
        $s5 = "src/core/os/windows/netbios.rs"
        $s6 = "[...] is out of bounds of `"
        $s7 = "expected char at offset "
        $s8 = "dependent_service_name="
        $s9 = "Did you mean ?"
        $s10 = "UnknownTagbyte"
        $s11 = "CoInitializeEx"
        $s12 = "decimal literal empty"
        $s13 = "rebroadcast_cache_to="
        $s14 = "Internal buffer full."
        $s15 = "src is out of bounds,"
        $s16 = "library\\std\\src\\path.rs"
        $s17 = "punycode{-0"
        $s18 = "?456789:;<="
        $s19 = "~I(k`9FUNnQ"
        $s20 = "search_kind"
condition:
    uint16(0) == 0x5a4d and filesize < 3401KB and
    4 of them
}
    
