rule Worm_CodeRed_A_exe {
strings:
        $s1 = "VirtualProtect"
        $s2 = "HOST:www.worm.com"
        $s3 = "TcpSockSend"
        $s4 = "c:\\notworm"
        $s5 = "infocomm.dll"
        $s6 = "LoadLibraryA"
        $s7 = " Accept: */*"
        $s8 = "CreateFileA"
        $s9 = "GetSystemTime"
        $s10 = "  HTTP/1.0"
        $s11 = "WS2_32.dll"
        $s12 = "CreateThread"
        $s13 = "closesocket"
        $s14 = "GET /default.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u00=a  HTTP/1.0"
        $s15 = "w3svc.dll"
        $s16 = "UWSVPj<"
        $s17 = "connect"
        $s18 = "socket"
        $s19 = ":LMTHu"
        $s20 = "X^[_]"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    