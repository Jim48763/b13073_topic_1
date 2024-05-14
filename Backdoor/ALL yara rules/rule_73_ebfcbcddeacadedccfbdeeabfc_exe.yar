rule ebfcbcddeacadedccfbdeeabfc_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "wX:#*EB`C=y"
        $s3 = "LoadStringW"
        $s4 = "ProgramFilesDir"
        $s5 = "DialogBoxParamW"
        $s6 = "IsWindowVisible"
        $s7 = "DispatchMessageW"
        $s8 = "GetModuleHandleW"
        $s9 = "CreateCompatibleBitmap"
        $s10 = "CryptUnprotectMemory"
        $s11 = "GetCurrentDirectoryW"
        $s12 = "SHBrowseForFolderW"
        $s13 = "GETPASSWORD1"
        $s14 = "SetEndOfFile"
        $s15 = "EnableWindow"
        $s16 = "UpdateWindow"
        $s17 = "OLEAUT32.dll"
        $s18 = "GetTickCount"
        $s19 = "</trustInfo>"
        $s20 = "MapViewOfFile"
condition:
    uint16(0) == 0x5a4d and filesize < 272KB and
    4 of them
}
    
