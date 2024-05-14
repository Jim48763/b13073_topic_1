rule fababdcffbaceacabbeeadeacce_exe {
strings:
        $s1 = "+121K1T1[1E2L207M7`7^9"
        $s2 = "GetKeyboardLayout"
        $s3 = "sqlite3_blob_open"
        $s4 = "EVariantDispatchError"
        $s5 = "TInterfacedPersistent"
        $s6 = "^UnitConnectionHelper"
        $s7 = "EVariantBadVarTypeError"
        $s8 = "GetDeviceDriverFileNameA"
        $s9 = "GetEnhMetaFilePaletteEntries"
        $s10 = "sqlite3_release_memory"
        $s11 = "GetExtendedUdpTable"
        $s12 = "sqlite3_mutex_enter"
        $s13 = "Unknown compression"
        $s14 = "sqlite3_result_blob"
        $s15 = "VirtualAllocEx"
        $s16 = "TBitmapCanvas<"
        $s17 = "sqlite3_malloc"
        $s18 = "DtServ32sm.exe"
        $s19 = "RegSetValueExA"
        $s20 = "CoCreateInstanceEx"
condition:
    uint16(0) == 0x5a4d and filesize < 616KB and
    4 of them
}
    
