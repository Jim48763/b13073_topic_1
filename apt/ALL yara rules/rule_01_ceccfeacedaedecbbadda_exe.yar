rule ceccfeacedaedecbbadda_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "1.0.6, 6-Sept-2010"
        $s3 = "?456789:;<="
        $s4 = "VarFileInfo"
        $s5 = "ADSInternal.exe"
        $s6 = "TerminateProcess"
        $s7 = "GetModuleHandleW"
        $s8 = "      %d blocks, %d sorted, %d scanned"
        $s9 = "      bytes: mapping %d, "
        $s10 = "S:(ML;;NW;;;S-1-16-0)"
        $s11 = "        reconstructing block ..."
        $s12 = "NetworkService.exe"
        $s13 = "VerifyVersionInfoW"
        $s14 = "OpenSCManagerW"
        $s15 = "selectors %d, "
        $s16 = "CreateNamedPipeW"
        $s17 = "GetTempFileNameW"
        $s18 = "RegCreateKeyExW"
        $s19 = "test of your memory system."
        $s20 = "NullSessionPipes"
condition:
    uint16(0) == 0x5a4d and filesize < 62KB and
    4 of them
}
    
