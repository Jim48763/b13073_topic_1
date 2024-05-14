rule cabcaeadfdaeefcefedae_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "O6`{1 oPRv4"
        $s3 = "V,o3 H4\"i+"
        $s4 = "{1MgKNJesQk"
        $s5 = "9eiImAV:J+("
        $s6 = "-YQ0?>\"JEV"
        $s7 = "waveOutSetVolume"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "GetCurrentThreadId"
        $s11 = "PathGetArgsW"
        $s12 = "GetTickCount"
        $s13 = "WNetCancelConnectionA"
        $s14 = "StringFromIID"
        $s15 = "SetHandleCount"
        $s16 = "DeleteCriticalSection"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "InterlockedDecrement"
        $s19 = "GetDeviceCaps"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 1880KB and
    4 of them
}
    
