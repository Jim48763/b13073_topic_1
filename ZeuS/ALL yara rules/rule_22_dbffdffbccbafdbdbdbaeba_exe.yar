rule dbffdffbccbafdbdbdbaeba_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "VarFileInfo"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleA"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetTickCount"
        $s7 = "asodjhioabsdf aisuodfhpiasdf piausdhfpaiosufh"
        $s8 = "odjsfhngs dfigjbsdf gisjdfgpjisodbfgpoijsdfng"
        $s9 = "SetHandleCount"
        $s10 = "CorExitProcess"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "InterlockedDecrement"
        $s13 = "Kuyagupejage jiku"
        $s14 = "VirtualProtect"
        $s15 = "g#Zp,~J3ru"
        $s16 = "z_W@\"'eG6"
        $s17 = "M@/=d W,<V"
        $s18 = "GetCurrentProcess"
        $s19 = "IsDebuggerPresent"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 246KB and
    4 of them
}
    
