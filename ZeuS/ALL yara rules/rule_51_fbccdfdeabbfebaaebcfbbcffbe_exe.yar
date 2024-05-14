rule fbccdfdeabbfebaaebcfbbcffbe_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "   * @param {string} str"
        $s3 = "  width: 16px;"
        $s4 = "Runtime Error!"
        $s5 = "          </paper-icon-button>"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "`local vftable'"
        $s9 = "FileDescription"
        $s10 = "NetShareGetInfo"
        $s11 = "SetDIBitsToDevice"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "IPv6 unavailable"
        $s15 = "DrawFrameControl"
        $s16 = "Image has no DIB"
        $s17 = "Not all bytes sent."
        $s18 = "      if (extensions_link)"
        $s19 = "CreateCompatibleDC"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 341KB and
    4 of them
}
    
