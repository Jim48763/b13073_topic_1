rule dfbcedaafcebbeeddebaaab_exe {
strings:
        $s1 = "Directory not empty"
        $s2 = "Runtime Error!"
        $s3 = "invalid string position"
        $s4 = "No child processes"
        $s5 = "9QM;F@TW\"$"
        $s6 = "LC_MONETARY"
        $s7 = "VarFileInfo"
        $s8 = "`local vftable'"
        $s9 = "spanish-venezuela"
        $s10 = "GetModuleHandleA"
        $s11 = "TerminateProcess"
        $s12 = "RemoveDirectoryW"
        $s13 = "Operation not permitted"
        $s14 = "GetCurrentThreadId"
        $s15 = "No locks available"
        $s16 = "SetEndOfFile"
        $s17 = "south-africa"
        $s18 = "Invalid seek"
        $s19 = "GetTickCount"
        $s20 = "IsValidLocale"
condition:
    uint16(0) == 0x5a4d and filesize < 310KB and
    4 of them
}
    
