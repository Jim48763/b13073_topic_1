rule dacaaebaebecefbeaffedfae_dll {
strings:
        $s1 = "midiOutGetNumDevs"
        $s2 = "GetCharacterPlacementW"
        $s3 = "LsaSetSystemAccessAccount"
        $s4 = "AccessibleChildren"
        $s5 = "FlushTraceA"
        $s6 = "PrintDlgExA"
        $s7 = "SHRegCloseUSKey"
        $s8 = "DrawStatusTextW"
        $s9 = "LPSAFEARRAY_Size"
        $s10 = "DAD_DragEnterEx2"
        $s11 = "DeletePrintProvidorW"
        $s12 = "winspool.drv"
        $s13 = "dwOKSubclass"
        $s14 = "waveOutClose"
        $s15 = "VarUI2FromR8"
        $s16 = "SetWindowRgn"
        $s17 = "MB_GetString"
        $s18 = "IsCharSpaceA"
        $s19 = "RemoveRelocations"
        $s20 = "AddPrinterDriverExA"
condition:
    uint16(0) == 0x5a4d and filesize < 577KB and
    4 of them
}
    
