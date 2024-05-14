rule babeebeddabedfebebafa_exe {
strings:
        $s1 = "cross device link"
        $s2 = "UnloadUserProfile"
        $s3 = "SetDefaultDllDirectories"
        $s4 = "CreateWindowStationW"
        $s5 = "executable format error"
        $s6 = "4 4$4(4,4044484D4H4L4P4T4`4d4h4L5P5T5X6\\6`6d6"
        $s7 = "result out of range"
        $s8 = "directory not empty"
        $s9 = "RegSetValueExW"
        $s10 = "invalid string position"
        $s11 = "operation canceled"
        $s12 = "AHKEY_CLASSES_ROOT"
        $s13 = "LogFilePath"
        $s14 = "`local vftable'"
        $s15 = "IsWindowVisible"
        $s16 = "DeviceIoControl"
        $s17 = "NetWkstaGetInfo"
        $s18 = "ReadProcessMemory"
        $s19 = "RemoveDirectoryW"
        $s20 = "ClientCustomData"
condition:
    uint16(0) == 0x5a4d and filesize < 230KB and
    4 of them
}
    
