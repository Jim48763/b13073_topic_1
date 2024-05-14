rule debefbdbcddbfedadccfdcdef_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "VirtualAllocEx"
        $s3 = "CoInitializeEx"
        $s4 = "GetUserNameExW"
        $s5 = "RtlNtStatusToDosError"
        $s6 = "eax=0x%p, ebx=0x%p, edx=0x%p, ecx=0x%p, esi=0x%p, edi=0x%p, ebp=0x%p, esp=0x%p, eip=0x%p"
        $s7 = "CopyFileExW"
        $s8 = "-<.8?5+19#'"
        $s9 = "|h>79N6;mpB"
        $s10 = "I^V]lZMHW@D"
        $s11 = "InternetCrackUrlA"
        $s12 = "RemoveDirectoryW"
        $s13 = "UnregisterClassW"
        $s14 = "GetComputerNameW"
        $s15 = "DispatchMessageW"
        $s16 = "GetModuleHandleA"
        $s17 = "CreateCompatibleBitmap"
        $s18 = "WriteProcessMemory"
        $s19 = "GetLocalTime"
        $s20 = "Flags=0x%08X"
condition:
    uint16(0) == 0x5a4d and filesize < 107KB and
    4 of them
}
    
