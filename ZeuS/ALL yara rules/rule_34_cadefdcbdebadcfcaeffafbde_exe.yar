rule cadefdcbdebadcfcaeffafbde_exe {
strings:
        $s1 = ")rMVPQEHeHHKG$"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "WSAGetLastError"
        $s5 = "FileDescription"
        $s6 = "O@CWe`OG!!!K^dL"
        $s7 = "GetShortPathNameA"
        $s8 = "GetComputerNameW"
        $s9 = "SetNamedPipeHandleState"
        $s10 = "WriteProcessMemory"
        $s11 = "GetLocalTime"
        $s12 = "SetEndOfFile"
        $s13 = "(rMVPQEHbVAA$"
        $s14 = "gethostbyname"
        $s15 = "VerifyVersionInfoW"
        $s16 = "FormatMessageW"
        $s17 = ")hKE@hMFVEV]e$"
        $s18 = "SetDllDirectoryW"
        $s19 = "RRPMO/3))&&%%U`"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 194KB and
    4 of them
}
    
