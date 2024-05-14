rule becdaedbeadffcbbeacad_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "LoadAcceleratorsW"
        $s3 = "msctls_progress32"
        $s4 = "english-caribbean"
        $s5 = "service_provider_name"
        $s6 = "CEFEGHIKLGIJFFFEEEEGHCEFFHI=?@JLMBBB"
        $s7 = ")+,%'(\"!#   444~~~"
        $s8 = "Are you sure to delete \" %s \""
        $s9 = "Add  Information     Insert"
        $s10 = "Fmsctls_statusbar32"
        $s11 = "\"%*&(2$&.!$)!$,%)."
        $s12 = "Find the specified text"
        $s13 = "`Rv[Mv]PvZKqtf"
        $s14 = "RegSetValueExW"
        $s15 = "CAliEditorView"
        $s16 = "CoRegisterMessageFilter"
        $s17 = "SetConsoleCtrlHandler"
        $s18 = "CoDisconnectObject"
        $s19 = ".?AVCPreviewView@@"
        $s20 = "J?S4+E4+E.(A( >.&E"
condition:
    uint16(0) == 0x5a4d and filesize < 1537KB and
    4 of them
}
    
