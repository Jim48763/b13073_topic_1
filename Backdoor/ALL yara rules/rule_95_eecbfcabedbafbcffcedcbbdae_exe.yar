rule eecbfcabedbafbcffcedcbbdae_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "`vector destructor iterator'"
        $s3 = "pllhhhgqpoowvutt||zz"
        $s4 = "\"\"\\~xX}yXzzXwtXusXqXX9)"
        $s5 = ">>?.==<;UU79_Nfdddddd3"
        $s6 = "Directory not empty"
        $s7 = "No child processes"
        $s8 = "[Y1~VUUTRRQQOOPPP>"
        $s9 = "GetConsoleOutputCP"
        $s10 = "ProductName"
        $s11 = "V,-+%?'(& N"
        $s12 = "VarFileInfo"
        $s13 = "S~|{zxvu3p&"
        $s14 = "FileDescription"
        $s15 = "`local vftable'"
        $s16 = "TerminateProcess"
        $s17 = "GetModuleHandleW"
        $s18 = "ConsoleApp42.exe"
        $s19 = "Operation not permitted"
        $s20 = "EnterCriticalSection"
condition:
    uint16(0) == 0x5a4d and filesize < 3053KB and
    4 of them
}
    
