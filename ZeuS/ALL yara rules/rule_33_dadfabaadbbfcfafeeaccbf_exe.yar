rule dadfabaadbbfcfafeeaccbf_exe {
strings:
        $s1 = "werdrtyuiopahertyu"
        $s2 = "CMP_Init_Detection"
        $s3 = "LoadStringW"
        $s4 = "@E(<g0Dr&\""
        $s5 = "CMu1h GXVet"
        $s6 = "DispatchMessageW"
        $s7 = "GetExpandedNameW"
        $s8 = "GetModuleHandleW"
        $s9 = "exrapi32.dll"
        $s10 = "WaitNamedPipeA"
        $s11 = "TraceSQLCancel"
        $s12 = "GetFileAttributesW"
        $s13 = "IsDialogMessageW"
        $s14 = "CountryRunOnce"
        $s15 = "CreateDesktopW"
        $s16 = "GetCurrentThread"
        $s17 = "GetTempPathW"
        $s18 = "CM_Add_Range"
        $s19 = "IsBadReadPtr"
        $s20 = "IsCharUpperA"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
