rule fcdfbadddaacdebffcdccfb_exe {
strings:
        $s1 = "dtoa_lock_cleanup"
        $s2 = "_URC_END_OF_STACK"
        $s3 = "valid_lead_string"
        $s4 = "NSt6locale5facetE"
        $s5 = "StartAddressOfRawData"
        $s6 = "guard variable for "
        $s7 = " __shmem_init_sjlj_once"
        $s8 = "__shmem_grabber_use_fc_key"
        $s9 = "covariant return thunk to "
        $s10 = "_pthread_key_sch_shmem"
        $s11 = "processthreadsapi.h"
        $s12 = "NumberOfLinenumbers"
        $s13 = "VT_VERSIONED_STREAM"
        $s14 = "__copybits_D2A"
        $s15 = "_beginthreadex"
        $s16 = "SizeOfUninitializedData"
        $s17 = "_ValidateImageBase"
        $s18 = ")check_managed_app"
        $s19 = "_URC_HANDLER_FOUND"
        $s20 = "short unsigned int"
condition:
    uint16(0) == 0x5a4d and filesize < 1231KB and
    4 of them
}
    
