rule eaffdfbefbbbfabecdceadbdbeadbecf_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "SetConsoleCtrlHandler"
        $s3 = "GetConsoleOutputCP"
        $s4 = "Z_^2{ o+}=&"
        $s5 = "v4|Dt,5\">h"
        $s6 = "N_bPY,*]<\""
        $s7 = "R:k#3`;_quL"
        $s8 = "M7=KmsY-,|<"
        $s9 = "VarFileInfo"
        $s10 = "/aVz\">I#sK"
        $s11 = "femaseparukomatul"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "EnterCriticalSection"
        $s15 = "WriteProcessMemory"
        $s16 = "{ioE!hOVE|xt"
        $s17 = "SetEndOfFile"
        $s18 = "t#U`~\"_rqU7"
        $s19 = "GetTickCount"
        $s20 = "\"da-aDIABg+"
condition:
    uint16(0) == 0x5a4d and filesize < 746KB and
    4 of them
}
    
