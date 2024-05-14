rule bffcabeefddfacecceebdd_exe {
strings:
        $s1 = "waveInGetPosition"
        $s2 = "CreateColorTransformA"
        $s3 = "CoDisconnectObject"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "QueryDosDeviceA"
        $s8 = "GetShortPathNameW"
        $s9 = "TranslateBitmapBits"
        $s10 = "midiOutClose"
        $s11 = "Full Version"
        $s12 = "UnlockFileEx"
        $s13 = ":+s6*b=]U:cP"
        $s14 = "SuspendThread"
        $s15 = "midiOutPrepareHeader"
        $s16 = "mciSendStringA"
        $s17 = "midiOutSetVolume"
        $s18 = "GetTempFileNameW"
        $s19 = "_abnormal_termination"
        $s20 = "GetFileAttributesW"
condition:
    uint16(0) == 0x5a4d and filesize < 109KB and
    4 of them
}
    
