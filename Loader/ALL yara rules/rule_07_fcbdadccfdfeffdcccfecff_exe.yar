rule fcbdadccfdfeffdcccfecff_exe {
strings:
        $s1 = "BufferedPaintInit"
        $s2 = "OleLoadFromStream"
        $s3 = "DRAGDROP_S_CANCEL"
        $s4 = "spanish-guatemala"
        $s5 = "DISP_E_BADVARTYPE"
        $s6 = "german-luxembourg"
        $s7 = "GetTouchInputInfo"
        $s8 = "request complete."
        $s9 = "%s: Execute '%s'."
        $s10 = ".\\UserImages.bmp"
        $s11 = "cross device link"
        $s12 = "WM_MDIICONARRANGE"
        $s13 = "english-caribbean"
        $s14 = "msctls_progress32"
        $s15 = "Create a new document"
        $s16 = "Incorrect use of null"
        $s17 = "Select &context menu:"
        $s18 = "DISP_E_NOTACOLLECTION"
        $s19 = "IDB_RIBBON_PANEL_BACK"
        $s20 = "OLE_E_CANT_GETMONIKER"
condition:
    uint16(0) == 0x5a4d and filesize < 12274KB and
    4 of them
}
    
