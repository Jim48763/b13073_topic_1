rule dcaccdeabebebaecaadebdfb_exe {
strings:
        $s1 = "lineGetLineDevStatus"
        $s2 = "lineGetConfRelatedCalls"
        $s3 = "STATUS_ACPI_ASSERT_FAILED"
        $s4 = "phoneGetStatusW"
        $s5 = "lineGetAddressIDA"
        $s6 = "lineGetCallInfoW"
        $s7 = "GetModuleHandleW"
        $s8 = "EnterCriticalSection"
        $s9 = "lineTranslateDialog"
        $s10 = "COMDLG32.dll"
        $s11 = "GetTickCount"
        $s12 = "lineSwapHold"
        $s13 = "lineSetCallParams"
        $s14 = "lineRemoveFromConference"
        $s15 = "BCS_EVENT_ASSOCIATION_SUCCESS"
        $s16 = "CLSIDFromProgID"
        $s17 = "lineTranslateAddressA"
        $s18 = "Greater Manchester1"
        $s19 = "lineRegisterRequestRecipient"
        $s20 = "lineBlindTransfer"
condition:
    uint16(0) == 0x5a4d and filesize < 187KB and
    4 of them
}
    
