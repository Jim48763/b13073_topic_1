rule aaabbcaecbcdddfadebdfcbaa_exe {
strings:
        $s1 = "sinstaller ce logiciel de gestion "
        $s2 = "policyConstraints"
        $s3 = "Trailer Field: 0x"
        $s4 = "spanish-guatemala"
        $s5 = "duk_bi_encoding.c"
        $s6 = "require('bignum')"
        $s7 = "german-luxembourg"
        $s8 = "id-cmc-dataReturn"
        $s9 = "encrypted track 2"
        $s10 = "OBJECT DESCRIPTOR"
        $s11 = "english-caribbean"
        $s12 = "getStartupOptions"
        $s13 = "GetEnvironmentStrings"
        $s14 = "DiagnosticCertificate"
        $s15 = "legacy_server_connect"
        $s16 = "414Q4B6H6x6U7i7p7c8"
        $s17 = "with in strict mode"
        $s18 = "secure device signature"
        $s19 = "id-on-permanentIdentifier"
        $s20 = "Invalid endian specified"
condition:
    uint16(0) == 0x5a4d and filesize < 3410KB and
    4 of them
}
    
