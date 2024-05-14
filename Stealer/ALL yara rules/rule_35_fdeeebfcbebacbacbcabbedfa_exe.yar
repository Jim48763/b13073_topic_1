rule fdeeebfcbebacbacbcabbedfa_exe {
strings:
        $s1 = "client handshake "
        $s2 = "encoded window_update"
        $s3 = "`at` split index (is "
        $s4 = "schedule_pending_open"
        $s5 = "PushPromisepromised_id"
        $s6 = "CreateIoCompletionPort"
        $s7 = "send body user stream error: "
        $s8 = "starting new connection: "
        $s9 = "sized write, len = "
        $s10 = "FramedWrite::bufferframe"
        $s11 = "SymInitializeW"
        $s12 = "header map reserve overflowed"
        $s13 = "checkout dropped for "
        $s14 = "RtlNtStatusToDosError"
        $s15 = "GetConsoleOutputCP"
        $s16 = "encoding chunked B"
        $s17 = "CONNECT : HTTP/1.1"
        $s18 = "sending data frame"
        $s19 = "Internal Hyper error, please report "
        $s20 = "0123456789:"
condition:
    uint16(0) == 0x5a4d and filesize < 2521KB and
    4 of them
}
    
