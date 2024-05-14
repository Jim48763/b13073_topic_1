rule efdccecefffeaecaebcfff_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "(NdoooomomoZZdPomomNNWNjLNNttwommiihmhjjhcN("
        $s3 = "CoInitializeEx"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "DeviceIoControl"
        $s10 = "DialogBoxParamA"
        $s11 = "`local vftable'"
        $s12 = "HttpEndRequestW"
        $s13 = "FileDescription"
        $s14 = "TerminateProcess"
        $s15 = "DrawFrameControl"
        $s16 = "GetModuleHandleA"
        $s17 = "9#p:9#p:9#_nextafter"
        $s18 = "46:::>:4:>A>@>A>AAHGDHHMIMTMMTTTTW6"
        $s19 = "CreateCompatibleDC"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 337KB and
    4 of them
}
    
