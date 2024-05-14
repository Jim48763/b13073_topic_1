rule eebdedcccfbadedeaaddbfedafdf_exe {
strings:
        $s1 = "122.15.210.128|igtmntina"
        $s2 = "RuntimeHelpers"
        $s3 = "get_ReceiveBufferSize"
        $s4 = "STAThreadAttribute"
        $s5 = "igtmntinafilesLogs"
        $s6 = "LastIndexOf"
        $s7 = "op_Equality"
        $s8 = "_CorExeMain"
        $s9 = "ProductName"
        $s10 = "PixelFormat"
        $s11 = "VarFileInfo"
        $s12 = "set_MinimizeBox"
        $s13 = "FileDescription"
        $s14 = "htintn-gtavprcs"
        $s15 = "get_MachineName"
        $s16 = "get_ProcessName"
        $s17 = "Form1_FormClosing"
        $s18 = "igtmntinadefaultP"
        $s19 = "DebuggerHiddenAttribute"
        $s20 = "InitializeComponent"
condition:
    uint16(0) == 0x5a4d and filesize < 9476KB and
    4 of them
}
    
