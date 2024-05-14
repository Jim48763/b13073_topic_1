rule bffdabbddacadccdaeabfbb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "InsertVariableBtn"
        $s5 = "DisabledImagesd>I"
        $s6 = "TStringSparseList"
        $s7 = "msctls_progress32"
        $s8 = "TPacketAttribute "
        $s9 = "NewCancelBtnClick"
        $s10 = "Possible deadlock"
        $s11 = "CoAddRefServerProcess"
        $s12 = "TInterfacedPersistent"
        $s13 = "GetEnvironmentStrings"
        $s14 = "Return current time as a string"
        $s15 = "EVariantBadVarTypeError"
        $s16 = "Unable to insert an item"
        $s17 = "'%s' is not a valid date"
        $s18 = "File already exists"
        $s19 = "DeviceCapabilitiesA"
        $s20 = "Invalid access code"
condition:
    uint16(0) == 0x5a4d and filesize < 1359KB and
    4 of them
}
    
