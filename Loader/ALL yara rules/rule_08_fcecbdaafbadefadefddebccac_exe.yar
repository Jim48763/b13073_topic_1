rule fcecbdaafbadefadefddebccac_exe {
strings:
        $s1 = "dtoa_lock_cleanup"
        $s2 = "_URC_END_OF_STACK"
        $s3 = "valid_lead_string"
        $s4 = "NSt6locale5facetE"
        $s5 = "StartAddressOfRawData"
        $s6 = "guard variable for "
        $s7 = "covariant return thunk to "
        $s8 = "_pthread_key_sch_shmem"
        $s9 = "processthreadsapi.h"
        $s10 = "VT_VERSIONED_STREAM"
        $s11 = "NumberOfLinenumbers"
        $s12 = "*__bigtens_D2A"
        $s13 = "\"__rshift_D2A"
        $s14 = "_beginthreadex"
        $s15 = "SizeOfUninitializedData"
        $s16 = "_ValidateImageBase"
        $s17 = ".check_managed_app"
        $s18 = "_URC_HANDLER_FOUND"
        $s19 = "short unsigned int"
        $s20 = "X86_ARCH_CMPXCHG8B"
condition:
    uint16(0) == 0x5a4d and filesize < 1183KB and
    4 of them
}
    
