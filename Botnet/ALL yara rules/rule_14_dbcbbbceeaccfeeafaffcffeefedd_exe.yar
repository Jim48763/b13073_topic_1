rule dbcbbbceeaccfeeafaffcffeefedd_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "CreateIoCompletionPort"
        $s3 = "<dependency><dependentAssembly>"
        $s4 = "_beginthreadex"
        $s5 = "GetWindowDC"
        $s6 = "MyDocuments"
        $s7 = "n z.\"lX/w7"
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "FileDescription"
        $s11 = "SetThreadLocale"
        $s12 = "DispatchMessageW"
        $s13 = "CreateJobObjectW"
        $s14 = "GetModuleHandleW"
        $s15 = "RemoveDirectoryW"
        $s16 = "CreateCompatibleBitmap"
        $s17 = "EnterCriticalSection"
        $s18 = "SetCurrentDirectoryW"
        $s19 = "Do you want to continue?"
        $s20 = "SHBrowseForFolderW"
condition:
    uint16(0) == 0x5a4d and filesize < 1108KB and
    4 of them
}
    
