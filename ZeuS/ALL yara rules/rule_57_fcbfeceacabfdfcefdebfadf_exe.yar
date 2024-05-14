rule fcbfeceacabfdfcefdebfadf_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "Create a new document"
        $s3 = "Find the specified text"
        $s4 = "Cancel Preview"
        $s5 = "Activate Task List"
        $s6 = "ProductName"
        $s7 = "Large Icons"
        $s8 = "VarFileInfo"
        $s9 = "FileDescription"
        $s10 = "GetModuleHandleA"
        $s11 = "Repeat the last action"
        $s12 = "Displays items in a list."
        $s13 = " Display full pages"
        $s14 = "PrivateBuild"
        $s15 = "UpdateWindow"
        $s16 = "EnableWindow"
        $s17 = "<<OLE VERBS GO HERE>>"
        $s18 = "Previous Pane"
        $s19 = "SysTreeView32"
        $s20 = "LegalTrademarks"
condition:
    uint16(0) == 0x5a4d and filesize < 235KB and
    4 of them
}
    
