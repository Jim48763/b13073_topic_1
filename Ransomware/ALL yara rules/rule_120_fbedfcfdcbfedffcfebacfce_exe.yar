rule fbedfcfdcbfedffcfebacfce_exe {
strings:
        $s1 = "CCLDVDEngine_Se_5"
        $s2 = "Create a new document"
        $s3 = "__CreateAor@D@2@@stde"
        $s4 = "Additional &Metadata..."
        $s5 = "Find the specified text"
        $s6 = "RegSetValueExA"
        $s7 = "GetConsoleOutputCP"
        $s8 = "Activate Task List"
        $s9 = "yEval_Resto"
        $s10 = "ProductName"
        $s11 = "#WAg%G]H<w!"
        $s12 = "VarFileInfo"
        $s13 = "`bx^h0@9diD"
        $s14 = "UDIO_STREAM"
        $s15 = "IsWindowVisible"
        $s16 = "DialogBoxParamW"
        $s17 = "DeviceIoControl"
        $s18 = "HttpEndRequestA"
        $s19 = "FileDescription"
        $s20 = "ROM_BKDR_SET_PI"
condition:
    uint16(0) == 0x5a4d and filesize < 413KB and
    4 of them
}
    