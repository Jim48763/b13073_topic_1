rule ceafebdecffffafcbccfe_exe {
strings:
        $s1 = "Svt_q{b:Ltlthm"
        $s2 = "CoInitializeEx"
        $s3 = "RegSetValueExW"
        $s4 = "ProductName"
        $s5 = "hk]tYI{EBV@"
        $s6 = "@,OAbWT}6x "
        $s7 = "VarFileInfo"
        $s8 = "5InterlockedDecrement"
        $s9 = "DialogBoxParamW"
        $s10 = "FileDescription"
        $s11 = "H7DecodePointer"
        $s12 = "'GetSystemTimeAsFileTime"
        $s13 = "SetupFindNextLine"
        $s14 = "RemoveDirectoryW"
        $s15 = "DispatchMessageW"
        $s16 = "GetComputerNameW"
        $s17 = "GetCurrentThreadId"
        $s18 = "GetLocalTime"
        $s19 = "lDestroyIcon"
        $s20 = "*MoveFileExW"
condition:
    uint16(0) == 0x5a4d and filesize < 179KB and
    4 of them
}
    
