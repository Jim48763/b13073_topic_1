rule bfcfcddedaaccacbdfddaeeabbef_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExW"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "IsWindowVisible"
        $s8 = "DialogBoxParamW"
        $s9 = "FileDescription"
        $s10 = "GetShortPathNameW"
        $s11 = "GetModuleHandleW"
        $s12 = "RemoveDirectoryW"
        $s13 = "DispatchMessageW"
        $s14 = "SetCurrentDirectoryW"
        $s15 = "SHBrowseForFolderW"
        $s16 = "EnableWindow"
        $s17 = "GetTickCount"
        $s18 = "SetWindowPos"
        $s19 = "RegEnumValueW"
        $s20 = "SysListView32"
condition:
    uint16(0) == 0x5a4d and filesize < 304KB and
    4 of them
}
    
