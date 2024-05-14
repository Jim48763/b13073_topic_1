rule afaefdedabbfcededfddaaaae_exe {
strings:
        $s1 = "waveInGetPosition"
        $s2 = "CreateColorTransformA"
        $s3 = "CoDisconnectObject"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "mIRhl=r3aKQ"
        $s7 = "FileDescription"
        $s8 = "QueryDosDeviceA"
        $s9 = "GetShortPathNameW"
        $s10 = "TranslateBitmapBits"
        $s11 = "midiOutClose"
        $s12 = "Full Version"
        $s13 = "UnlockFileEx"
        $s14 = "6d92aDaNAr1i"
        $s15 = "SuspendThread"
        $s16 = "midiOutPrepareHeader"
        $s17 = "mciSendStringA"
        $s18 = "midiOutSetVolume"
        $s19 = "GetTempFileNameW"
        $s20 = "_abnormal_termination"
condition:
    uint16(0) == 0x5a4d and filesize < 1029KB and
    4 of them
}
    
