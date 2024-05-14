rule cefabdafbbcaeefdeafecbfafde_exe {
strings:
        $s1 = "$0086e4fb-e603-4c03-bef6-fd8b6e700367"
        $s2 = "RuntimeHelpers"
        $s3 = "RuntimeFieldHandle"
        $s4 = "ProductName"
        $s5 = "_CorExeMain"
        $s6 = "K7P;T=]a#[V"
        $s7 = ", \"a8.XOM6"
        $s8 = "VarFileInfo"
        $s9 = "+Lgb6Pqza@_"
        $s10 = "FileDescription"
        $s11 = "FlushFinalBlock"
        $s12 = "get_IsBrowserHosted"
        $s13 = "SecurityCriticalAttribute"
        $s14 = "Synchronized"
        $s15 = "Durbanville1"
        $s16 = "BBd',N^R}_ %"
        $s17 = "']aeCKr#\\O$"
        $s18 = "IAsyncResult"
        $s19 = "System.Resources"
        $s20 = "StringBuilder"
condition:
    uint16(0) == 0x5a4d and filesize < 813KB and
    4 of them
}
    
