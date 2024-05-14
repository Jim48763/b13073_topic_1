rule cedbfdacdedfebddbfebdade_exe {
strings:
        $s1 = "terminals database is inaccessible"
        $s2 = "ASN1_IA5STRING_it"
        $s3 = "spanish-guatemala"
        $s4 = "german-luxembourg"
        $s5 = "[C]hange settings"
        $s6 = "0&1G1a1q1F4,6|6l:"
        $s7 = "API not running%s"
        $s8 = "*Thread Zero Hash"
        $s9 = "optionalSignature"
        $s10 = "UI_destroy_method"
        $s11 = "DES_read_password"
        $s12 = "[G]PU management "
        $s13 = "Only Some Reasons"
        $s14 = "encrypted track 2"
        $s15 = "PROCESS_PCI_VALUE"
        $s16 = "bad function call"
        $s17 = "cross device link"
        $s18 = "id-cmc-dataReturn"
        $s19 = "OBJECT DESCRIPTOR"
        $s20 = "english-caribbean"
condition:
    uint16(0) == 0x5a4d and filesize < 5668KB and
    4 of them
}
    
