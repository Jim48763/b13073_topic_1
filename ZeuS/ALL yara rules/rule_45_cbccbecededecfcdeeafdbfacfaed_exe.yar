rule cbccbecededecfcdeeafdbfacfaed_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "VirtualAllocEx"
        $s3 = "CoInitializeEx"
        $s4 = "GetUserNameExW"
        $s5 = "RtlNtStatusToDosError"
        $s6 = "CopyFileExW"
        $s7 = "InternetCrackUrlA"
        $s8 = "RemoveDirectoryW"
        $s9 = "UnregisterClassW"
        $s10 = "GetComputerNameW"
        $s11 = "DispatchMessageW"
        $s12 = "GetModuleHandleA"
        $s13 = "CreateCompatibleBitmap"
        $s14 = "WriteProcessMemory"
        $s15 = "SetEndOfFile"
        $s16 = "GetTickCount"
        $s17 = "OLEAUT32.dll"
        $s18 = "PathSkipRootW"
        $s19 = "GdiplusStartup"
        $s20 = "RegCreateKeyExW"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
