rule debdcbbfdecfdddeeaebbcd_exe {
strings:
        $s1 = "StartAddressOfRawData"
        $s2 = "_Jv_RegisterClasses"
        $s3 = "short unsigned int"
        $s4 = "gbl-ctors.h"
        $s5 = "wnkl;M14RY^"
        $s6 = "X86_TUNE_USE_SAHF"
        $s7 = "ix86_tune_indices"
        $s8 = "GetModuleHandleA"
        $s9 = "VT_ILLEGALMASKED"
        $s10 = "X86_TUNE_UNROLL_STRLEN"
        $s11 = "InitializeCriticalSection"
        $s12 = "ContextFlags"
        $s13 = "OwningThread"
        $s14 = "_startupinfo"
        $s15 = "__cpu_features_init"
        $s16 = "LockSemaphore"
        $s17 = "key_dtor_list"
        $s18 = "X86_ARCH_LAST"
        $s19 = "complex float"
        $s20 = "dummy_environ"
condition:
    uint16(0) == 0x5a4d and filesize < 631KB and
    4 of them
}
    
