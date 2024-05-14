rule acacfcfdeaaacbdbbcfd_exe {
strings:
        $s1 = "RegSetValueExA"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "GetKeyboardType"
        $s7 = "FileDescription"
        $s8 = "GetThreadLocale"
        $s9 = "GetShortPathNameA"
        $s10 = "GetModuleHandleA"
        $s11 = "CreateCompatibleBitmap"
        $s12 = "SetCurrentDirectoryA"
        $s13 = "GetCurrentThreadId"
        $s14 = "Hajfldtxhuhz"
        $s15 = "GetLocalTime"
        $s16 = "Synchronized"
        $s17 = "FPUMaskValue"
        $s18 = "SetEndOfFile"
        $s19 = "System.Resources"
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 230KB and
    4 of them
}
    
