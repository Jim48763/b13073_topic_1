rule ebbcabdbecaebeedc_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "InsertVariableBtn"
        $s5 = "msctls_progress32"
        $s6 = "NewCancelBtnClick"
        $s7 = "Possible deadlock"
        $s8 = "TToolDockFormd\"H"
        $s9 = "CoAddRefServerProcess"
        $s10 = "TInterfacedPersistent"
        $s11 = "GetEnvironmentStrings"
        $s12 = "Return current time as a string"
        $s13 = "EVariantBadVarTypeError"
        $s14 = "Unable to insert an item"
        $s15 = "'%s' is not a valid date"
        $s16 = "?(?<?D?H?L?P?T?X?\\?L;P;T;X;\\;`;d;h;l;p;t;x;|;"
        $s17 = "< <0<?<C<U<Y<*7B7F7J7N7R7V7Z7h7w7{7"
        $s18 = "File already exists"
        $s19 = "DeviceCapabilitiesA"
        $s20 = "Invalid access code"
condition:
    uint16(0) == 0x5a4d and filesize < 1266KB and
    4 of them
}
    
