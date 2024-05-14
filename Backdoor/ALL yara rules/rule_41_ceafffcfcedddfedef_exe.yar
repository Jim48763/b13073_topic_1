rule ceafffcfcedddfedef_exe {
strings:
        $s1 = "roigtbraorn-seaarf=|roigtbraorn"
        $s2 = "RuntimeHelpers"
        $s3 = "get_ReceiveBufferSize"
        $s4 = "STAThreadAttribute"
        $s5 = "ProductName"
        $s6 = "PixelFormat"
        $s7 = "LastIndexOf"
        $s8 = "VarFileInfo"
        $s9 = "_CorExeMain"
        $s10 = "get_MachineName"
        $s11 = "FileDescription"
        $s12 = "get_ProcessName"
        $s13 = "GetDirectoryName"
        $s14 = "jlthagniasmainvp"
        $s15 = "DebuggerHiddenAttribute"
        $s16 = "roigtbraorn.Properties"
        $s17 = "AssemblyCultureAttribute"
        $s18 = "InitializeComponent"
        $s19 = "windows|roigtbraorn"
        $s20 = "roigtbraornfiale_info"
condition:
    uint16(0) == 0x5a4d and filesize < 9972KB and
    4 of them
}
    
