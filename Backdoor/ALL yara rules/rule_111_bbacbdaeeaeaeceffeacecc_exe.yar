rule bbacbdaeeaeaeceffeacecc_exe {
strings:
        $s1 = "1d1521d1-9ba5-4c36-acd0-ca214c195b9c"
        $s2 = "18a97ca0-ac33-4818-8134-e3c873545986"
        $s3 = "ddd995ed-1494-4808-8d06-e59a4942b304"
        $s4 = "c00566eb-a84c-49fb-8b54-9bbc7a564cb5"
        $s5 = "90e69578-80f8-4f9e-8cf9-d197cc119f14"
        $s6 = "8378c0ca-7fa1-4a8f-8389-ae730f1f687e"
        $s7 = "0f3f2e8f-b07d-47d8-b800-d8e444e13277"
        $s8 = "2725f99e-2aec-4ce7-8a4c-a55685ca8426"
        $s9 = "9ba368af-09c4-45a7-aac7-f34864909aca"
        $s10 = "3d492704-4fff-49ea-bfa1-d91a2bdb4a41"
        $s11 = "fb2befbc-f564-4687-af67-5fbd42fa27a6"
        $s12 = "f17b6fdb-fa89-4f44-8beb-aa788ee636ff"
        $s13 = "f0c3a402-4f1a-408a-afaa-c811b08d2912"
        $s14 = "448dd418-c8be-4bcf-8fd1-a7fa0424b8d7"
        $s15 = "4e406e9e-65e9-4fe0-bdba-5694c461ac4b"
        $s16 = "dd8ae445-b51e-48ec-b8e4-446e5fd9fdc1"
        $s17 = "407c8462-a212-416d-9c94-286a6172096d"
        $s18 = "00e8117a-9b87-460e-88e2-17899b7fe706"
        $s19 = "5c9c04d0-71dd-43c8-8368-570071d68d98"
        $s20 = "8dd86845-a45c-43aa-abbf-83fd666bde4c"
condition:
    uint16(0) == 0x5a4d and filesize < 1306KB and
    4 of them
}
    
