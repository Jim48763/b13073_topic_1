rule fbafbeefcfdebdcceebfbdbabd_exe {
strings:
        $s1 = "_vsnprintf_helper"
        $s2 = "(ch != _T('\\0'))"
        $s3 = "2024282T7X7\\7d>h>l>p>t>"
        $s4 = "<file unknown>"
        $s5 = "Runtime Error!"
        $s6 = "Kugutabejonu jotino toguti bige"
        $s7 = "BackupWrite"
        $s8 = "`local vftable'"
        $s9 = "legipekewoculosas"
        $s10 = "CreateJobObjectA"
        $s11 = "GetModuleHandleA"
        $s12 = "GetComputerNameA"
        $s13 = "SetCurrentDirectoryA"
        $s14 = "mepohuyolomezomixitaxo"
        $s15 = "Tikiliximum fihewev"
        $s16 = "GetConsoleCursorInfo"
        $s17 = "(((_Src))) != NULL"
        $s18 = "GetCurrentThreadId"
        $s19 = "SetLocalTime"
        $s20 = "Expression: "
condition:
    uint16(0) == 0x5a4d and filesize < 343KB and
    4 of them
}
    
