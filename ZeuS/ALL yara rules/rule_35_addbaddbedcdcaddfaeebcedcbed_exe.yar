rule addbaddbedcdcaddfaeebcedcbed_exe {
strings:
        $s1 = "GetConsoleOutputCP"
        $s2 = "`local vftable'"
        $s3 = "SetFilePointerEx"
        $s4 = "TerminateProcess"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetTickCount"
        $s7 = "FindFirstFileExA"
        $s8 = "IIDFromString"
        $s9 = "GetMenuStringW"
        $s10 = "CorExitProcess"
        $s11 = "LoadLibraryExW"
        $s12 = "CreateMailslotW"
        $s13 = "`udt returning'"
        $s14 = "GetSystemTimeAsFileTime"
        $s15 = "VirtualProtect"
        $s16 = "GetProcessHeap"
        $s17 = "IsProcessorFeaturePresent"
        $s18 = "GetCurrentProcess"
        $s19 = "7 7$7(7,7074787<7@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7"
        $s20 = "3 3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
condition:
    uint16(0) == 0x5a4d and filesize < 205KB and
    4 of them
}
    
