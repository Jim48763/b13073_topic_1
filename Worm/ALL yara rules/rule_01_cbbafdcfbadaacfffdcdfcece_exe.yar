rule cbbafdcfbadaacfffdcdfcece_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "Contact PrestoSoft"
        $s3 = "&Arguments:"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "Fi&nd what:"
        $s7 = "DeviceIoControl"
        $s8 = "Enter File Type"
        $s9 = "&Change Font..."
        $s10 = "FileDescription"
        $s11 = "SetFilePointerEx"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "SetCurrentDirectoryW"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "Ignore &case"
        $s17 = "GetClassWord"
        $s18 = "SetEndOfFile"
        $s19 = "GetTickCount"
        $s20 = "FindFirstFileExA"
condition:
    uint16(0) == 0x5a4d and filesize < 1861KB and
    4 of them
}
    
