rule bdcbdfcadcfdedffabceecfdb_exe {
strings:
        $s1 = "ExitProcess"
        $s2 = "KERNEL32.dll"
        $s3 = "VirtualAlloc"
        $s4 = "AXAX^YZAXAYAZH"
        $s5 = "AQAPRQVH1"
        $s6 = "PAYLOAD:"
        $s7 = "VPAPAPAPI"
        $s8 = "`.rdata"
        $s9 = "Rich}E"
        $s10 = "@.mkxe"
        $s11 = "ws2_32"
        $s12 = "XAYZH"
        $s13 = ".text"
        $s14 = "APAPH"
        $s15 = "WWWM1"
condition:
    uint16(0) == 0x5a4d and filesize < 12KB and
    4 of them
}
    