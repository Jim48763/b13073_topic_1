rule caddaebbbbedaeceadacdcddc_exe {
strings:
        $s1 = "actualUnderlength"
        $s2 = "duplicate field `"
        $s3 = "fatal runtime error: "
        $s4 = "[...] is out of bounds of `"
        $s5 = "expected char at offset "
        $s6 = "dependent_service_name="
        $s7 = "Did you mean ?"
        $s8 = "UnknownTagbyte"
        $s9 = "CoInitializeEx"
        $s10 = "library\\std\\src\\net\\addr.rs:"
        $s11 = "decimal literal empty"
        $s12 = "rebroadcast_cache_to="
        $s13 = "Internal buffer full."
        $s14 = "punycode{-0"
        $s15 = "?456789:;<="
        $s16 = "~I(k`9FUNnQ"
        $s17 = "search_kind"
        $s18 = "DeviceIoControl"
        $s19 = "Process32FirstW"
        $s20 = "CONTEXT-SPECIFIC "
condition:
    uint16(0) == 0x5a4d and filesize < 3014KB and
    4 of them
}
    
