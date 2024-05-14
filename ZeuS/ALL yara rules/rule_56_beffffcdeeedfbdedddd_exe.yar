rule beffffcdeeedfbdedddd_exe {
strings:
        $s1 = "@rI/nCB([te"
        $s2 = "ProductName"
        $s3 = "FoO pBM=dA0"
        $s4 = "LoadStringA"
        $s5 = "VarFileInfo"
        $s6 = "DeviceIoControl"
        $s7 = "DialogBoxParamA"
        $s8 = "FileDescription"
        $s9 = "8' 3i,?3s,N#J,e#"
        $s10 = "DispatchMessageA"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleA"
        $s13 = "Microsoft Corporation"
        $s14 = "GetCurrentThreadId"
        $s15 = "SHBrowseForFolderA"
        $s16 = "UpdateWindow"
        $s17 = "EnableWindow"
        $s18 = "GetTickCount"
        $s19 = "MapViewOfFile"
        $s20 = "InvalidateRect"
condition:
    uint16(0) == 0x5a4d and filesize < 183KB and
    4 of them
}
    
