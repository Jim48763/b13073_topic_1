rule faecabcecaeccdefbbccdccc_exe {
strings:
        $s1 = "id-cmc-dataReturn"
        $s2 = "process_pci_value"
        $s3 = "encrypted track 2"
        $s4 = "Trailer Field: 0x"
        $s5 = "try_decode_params"
        $s6 = "OBJECT DESCRIPTOR"
        $s7 = "ts_check_imprints"
        $s8 = "CRLDistributionPoints"
        $s9 = "variable has no value"
        $s10 = "legacy_server_connect"
        $s11 = "extension value error"
        $s12 = "tls_process_client_certificate"
        $s13 = "tls_construct_cert_status_body"
        $s14 = "secure device signature"
        $s15 = "tls_construct_hello_retry_request"
        $s16 = "ssl_cipher_strength_sort"
        $s17 = "originatorSignatureValue"
        $s18 = "ssl_check_srvr_ecc_cert_and_alg"
        $s19 = "use_certificate_chain_file"
        $s20 = "Listing certs for store %s"
condition:
    uint16(0) == 0x5a4d and filesize < 8502KB and
    4 of them
}
    
