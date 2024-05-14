rule cccafbaddddbcfbece_exe {
strings:
        $s1 = "_URC_END_OF_STACK"
        $s2 = "StartAddressOfRawData"
        $s3 = "guard variable for "
        $s4 = "covariant return thunk to "
        $s5 = "_pthread_key_sch_shmem"
        $s6 = "processthreadsapi.h"
        $s7 = "VT_VERSIONED_STREAM"
        $s8 = "NumberOfLinenumbers"
        $s9 = "_beginthreadex"
        $s10 = "SizeOfUninitializedData"
        $s11 = "_ValidateImageBase"
        $s12 = ".check_managed_app"
        $s13 = "_URC_HANDLER_FOUND"
        $s14 = "short unsigned int"
        $s15 = "X86_ARCH_CMPXCHG8B"
        $s16 = "ProductName"
        $s17 = "gbl-ctors.h"
        $s18 = "FireCat.png"
        $s19 = "VarFileInfo"
        $s20 = "maxSections"
condition:
    uint16(0) == 0x5a4d and filesize < 892KB and
    4 of them
}
    
