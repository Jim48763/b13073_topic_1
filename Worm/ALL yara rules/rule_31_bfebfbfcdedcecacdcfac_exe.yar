rule bfebfbfcdedcecacdcfac_exe {
strings:
        $s1 = "http\\shell\\open\\command"
        $s2 = "CryptReleaseContext"
        $s3 = "RegSetValueExA"
        $s4 = "uURLHistory"
        $s5 = "?456789:;<="
        $s6 = "Heap32First"
        $s7 = "RAS Passwords |"
        $s8 = "ProgramFilesDir"
        $s9 = "Process32FirstW"
        $s10 = "ReadProcessMemory"
        $s11 = "DispatchMessageA"
        $s12 = "GetModuleHandleA"
        $s13 = "GetCurrentThreadId"
        $s14 = "6UnitSandBox"
        $s15 = "mozcrt19.dll"
        $s16 = "Thread32Next"
        $s17 = ";i`3CGZ6<VuC"
        $s18 = "GetTickCount"
        $s19 = "RegEnumValueA"
        $s20 = "PK11_FreeSlot"
condition:
    uint16(0) == 0x5a4d and filesize < 288KB and
    4 of them
}
    
