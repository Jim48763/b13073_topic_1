rule cfcdabfbbaeadbcabfaeefdfdae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "VarFileInfo"
        $s6 = "IsWindowVisible"
        $s7 = "DialogBoxParamA"
        $s8 = "FileDescription"
        $s9 = "GetModuleHandleA"
        $s10 = "DispatchMessageA"
        $s11 = "SHBrowseForFolderA"
        $s12 = "EnableWindow"
        $s13 = "GetTickCount"
        $s14 = "SetWindowPos"
        $s15 = "RegEnumValueA"
        $s16 = "SysListView32"
        $s17 = "GetWindowRect"
        $s18 = "IIDFromString"
        $s19 = "CloseClipboard"
        $s20 = "InvalidateRect"
condition:
    uint16(0) == 0x5a4d and filesize < 85KB and
    4 of them
}
    
