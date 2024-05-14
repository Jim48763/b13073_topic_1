rule cefabdafbbcaeefdeafecbfafde_exe {
strings:
        $s1 = "$0086e4fb-e603-4c03-bef6-fd8b6e700367"
        $s2 = "RuntimeHelpers"
        $s3 = ", \"a8.XOM6"
        $s4 = "K7P;T=]a#[V"
        $s5 = "_CorExeMain"
        $s6 = "ProductName"
        $s7 = "+Lgb6Pqza@_"
        $s8 = "VarFileInfo"
        $s9 = "FileDescription"
        $s10 = "FlushFinalBlock"
        $s11 = "get_IsBrowserHosted"
        $s12 = "SecurityCriticalAttribute"
        $s13 = "Synchronized"
        $s14 = "IAsyncResult"
        $s15 = "']aeCKr#\\O$"
        $s16 = "Durbanville1"
        $s17 = "BBd',N^R}_ %"
        $s18 = "StringBuilder"
        $s19 = "GeneratedCodeAttribute"
        $s20 = "System.Security"
condition:
    uint16(0) == 0x5a4d and filesize < 813KB and
    4 of them
}
    
