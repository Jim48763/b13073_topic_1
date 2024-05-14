rule cecaeacebecafbddcbaaeebc_exe {
strings:
        $s1 = "FOR USING OUR SERVICE"
        $s2 = "c:/file.ojs"
        $s3 = "fLX0RwJhHA~"
        $s4 = ",WB&~xr{1Ap"
        $s5 = ".dg+a[ZEvI:"
        $s6 = "@TZDSk5XPJM"
        $s7 = "f-~}N4)\"iK"
        $s8 = "hqmy7;9r{2&"
        $s9 = "OpenColorProfileA"
        $s10 = "GetConsoleWindow"
        $s11 = "OLEAUT32.dll"
        $s12 = "Phone Number"
        $s13 = "COMDLG32.dll"
        $s14 = "PageSetupDlgA"
        $s15 = "midiOutPrepareHeader"
        $s16 = " Enter amount:"
        $s17 = "GetSaveFileNameA"
        $s18 = " Phone No.: %s"
        $s19 = "\"_&n>Zij%"
        $s20 = "37'fnDht%V"
condition:
    uint16(0) == 0x5a4d and filesize < 1577KB and
    4 of them
}
    
