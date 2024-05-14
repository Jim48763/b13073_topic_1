rule deaabbdedcfebacebe_exe {
strings:
        $s1 = "actualUnderlength"
        $s2 = "duplicate field `"
        $s3 = "a tuple of size 2"
        $s4 = "floating point `$"
        $s5 = "fatal runtime error: "
        $s6 = "[...] is out of bounds of `"
        $s7 = "expected char at offset "
        $s8 = "dependent_service_name="
        $s9 = "Did you mean ?"
        $s10 = "UnknownTagbyte"
        $s11 = "CoInitializeEx"
        $s12 = "decimal literal empty"
        $s13 = "Internal buffer full."
        $s14 = "punycode{-0"
        $s15 = "?456789:;<="
        $s16 = "~I(k`9FUNnQ"
        $s17 = "try_unlock="
        $s18 = "search_kind"
        $s19 = "DeviceIoControl"
        $s20 = "Process32FirstW"
condition:
    uint16(0) == 0x5a4d and filesize < 2929KB and
    4 of them
}
    
