rule fbbaccedbafdbfdffffc_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "OnContextPopupXAP"
        $s5 = "TControlCanvasP<P"
        $s6 = "msctls_progress32"
        $s7 = "TPacketAttribute "
        $s8 = "TCustomStaticText"
        $s9 = "Possible deadlock"
        $s10 = "CoAddRefServerProcess"
        $s11 = "TCustomDropDownButton"
        $s12 = "EUnsupportedTypeError"
        $s13 = "TInterfacedPersistent"
        $s14 = "< <$<(<,<0<4<8<<<@<B8F8J8N8R8V8Z8^8b8f8j8n8r8v8"
        $s15 = "Unable to insert an item"
        $s16 = "'%s' is not a valid date"
        $s17 = "TCustomActionControl"
        $s18 = "File already exists"
        $s19 = "Invalid access code"
        $s20 = "Directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1581KB and
    4 of them
}
    
