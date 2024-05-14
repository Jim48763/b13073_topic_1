rule afeafbdecaafeccefea_exe {
strings:
        $s1 = "TMapTemporaryFile"
        $s2 = "EVariantBadVarTypeError"
        $s3 = "TSxsGenerateContext_Seven"
        $s4 = "VirtualAllocEx"
        $s5 = "CoInitializeEx"
        $s6 = "ZwResumeThread"
        $s7 = "CoCreateInstanceEx"
        $s8 = "System.Linq"
        $s9 = "ProductName"
        $s10 = "gJwaWinType"
        $s11 = "(Win32Types"
        $s12 = "poMnLHT8{-z"
        $s13 = "_CorExeMain"
        $s14 = "CVirtualBox"
        $s15 = "LoadStringA"
        $s16 = "R?2/(X[Y+8D"
        $s17 = "GetKeyboardType"
        $s18 = "TntWideStrUtils"
        $s19 = "get_VolumeLabel"
        $s20 = "DeviceIoControl"
condition:
    uint16(0) == 0x5a4d and filesize < 920KB and
    4 of them
}
    
