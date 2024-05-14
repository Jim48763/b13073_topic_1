rule ebadccfdbbacddbbfdabbcdeef_exe {
strings:
        $s1 = "obj_attr_oldvalue"
        $s2 = "child == array[i]"
        $s3 = "imm.y=imm_ptr[1];"
        $s4 = "try_decode_params"
        $s5 = "[0;3%dm (%1.1f%%)"
        $s6 = "process_pci_value"
        $s7 = "optionalSignature"
        $s8 = "Trailer Field: 0x"
        $s9 = "ts_check_imprints"
        $s10 = "Only Some Reasons"
        $s11 = "encrypted track 2"
        $s12 = "id-cmc-dataReturn"
        $s13 = "OBJECT DESCRIPTOR"
        $s14 = "invalid digest length"
        $s15 = "variable has no value"
        $s16 = "if(inst.y&(inst.y-1))"
        $s17 = "legacy_server_connect"
        $s18 = "missing psk kex modes extension"
        $s19 = "C[t]=A[s]^A[s+5]^A[s+10]^A[s+15]^A[s+20];"
        $s20 = "guard variable for "
condition:
    uint16(0) == 0x5a4d and filesize < 8005KB and
    4 of them
}
    