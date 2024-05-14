rule decacfdefeecbaaffddcadfd_exe {
strings:
        $s1 = "id-cmc-dataReturn"
        $s2 = "cross device link"
        $s3 = "X400-Content-Type"
        $s4 = "process_pci_value"
        $s5 = "encrypted track 2"
        $s6 = "Trailer Field: 0x"
        $s7 = "bad function call"
        $s8 = "OBJECT DESCRIPTOR"
        $s9 = "ts_check_imprints"
        $s10 = "CRLDistributionPoints"
        $s11 = "variable has no value"
        $s12 = "legacy_server_connect"
        $s13 = "extension value error"
        $s14 = "secure device signature"
        $s15 = "ssl_cipher_strength_sort"
        $s16 = "originatorSignatureValue"
        $s17 = "ssl_check_srvr_ecc_cert_and_alg"
        $s18 = "use_certificate_chain_file"
        $s19 = "Listing certs for store %s"
        $s20 = "extendedCertificateAttributes"
condition:
    uint16(0) == 0x5a4d and filesize < 2096KB and
    4 of them
}
    
