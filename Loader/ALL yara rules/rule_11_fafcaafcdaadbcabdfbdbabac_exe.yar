rule fafcaafcdaadbcabdfbdbabac_exe {
strings:
        $s1 = "dtoa_lock_cleanup"
        $s2 = "_URC_END_OF_STACK"
        $s3 = "StartAddressOfRawData"
        $s4 = "guard variable for "
        $s5 = " __shmem_init_sjlj_once"
        $s6 = "__shmem_grabber_use_fc_key"
        $s7 = "covariant return thunk to "
        $s8 = "KADWEGAFSTWUATQFFFFkxcEEF"
        $s9 = "_pthread_key_sch_shmem"
        $s10 = "processthreadsapi.h"
        $s11 = "NumberOfLinenumbers"
        $s12 = "VT_VERSIONED_STREAM"
        $s13 = ")__bigtens_D2A"
        $s14 = "_beginthreadex"
        $s15 = "SizeOfUninitializedData"
        $s16 = "_ValidateImageBase"
        $s17 = ")check_managed_app"
        $s18 = "_URC_HANDLER_FOUND"
        $s19 = "short unsigned int"
        $s20 = "X86_ARCH_CMPXCHG8B"
condition:
    uint16(0) == 0x5a4d and filesize < 865KB and
    4 of them
}
    
