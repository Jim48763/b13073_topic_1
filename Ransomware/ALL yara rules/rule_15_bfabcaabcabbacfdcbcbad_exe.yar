rule bfabcaabcabbacfdcbcbad_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExW"
        $s5 = "o&[]+)G4?uH"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "o8Y7\"fKjdM"
        $s9 = "IsWindowVisible"
        $s10 = "DialogBoxParamW"
        $s11 = "FileDescription"
        $s12 = "GetShortPathNameW"
        $s13 = "GetModuleHandleA"
        $s14 = "RemoveDirectoryW"
        $s15 = "ImageList_Create"
        $s16 = "DispatchMessageW"
        $s17 = "SetCurrentDirectoryW"
        $s18 = "SHBrowseForFolderW"
        $s19 = "GetTickCount"
        $s20 = "EnableWindow"
condition:
    uint16(0) == 0x5a4d and filesize < 477KB and
    4 of them
}
    
