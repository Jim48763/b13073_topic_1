import pe
rule eddedaedceffcaadd_exe {
strings:
        $s1 = "asn1:\"optional\""
        $s2 = "runtime.assertI2I"
        $s3 = "*[]map[string]int"
        $s4 = "runtime.runqsteal"
        $s5 = "crypto/md5/md5.go"
        $s6 = "dvnzzn7I.IAVJsdlV"
        $s7 = "net.SplitHostPort"
        $s8 = "*regexp.runeSlice"
        $s9 = "timerModifiedEarliest"
        $s10 = "runtime.cansemacquire"
        $s11 = "FirstMulticastAddress"
        $s12 = "syscall.CreateProcessAsUser"
        $s13 = "runtime.getproccount"
        $s14 = "type..eq.runtime.mOS"
        $s15 = "*cipher.cbcEncrypter"
        $s16 = "runtime.selectnbsend"
        $s17 = "os/exec.lookExtensions"
        $s18 = "runtime.queuefinalizer"
        $s19 = "CreateIoCompletionPort"
        $s20 = "fatal error: cgo callback before cgo call"
condition:
    uint16(0) == 0x5a4d and filesize < 3120KB and
    4 of them
}
    
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
    