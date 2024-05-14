rule bbfaedbbdffedbdebfbdaefc_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "ProductName"
        $s3 = "SUVWj@Ph|$B"
        $s4 = "VarFileInfo"
        $s5 = "FileDescription"
        $s6 = "TerminateProcess"
        $s7 = "GetModuleHandleA"
        $s8 = "IsBadCodePtr"
        $s9 = "PrivateBuild"
        $s10 = "__MSVCRT_HEAP_SELECT"
        $s11 = ";8967452330011"
        $s12 = "SetHandleCount"
        $s13 = "GetProcessHeap"
        $s14 = "VirtualProtect"
        $s15 = "LegalTrademarks"
        $s16 = "GetCurrentProcess"
        $s17 = "ExitProcess"
        $s18 = "HeapDestroy"
        $s19 = "SpecialBuild"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 153KB and
    4 of them
}
    
