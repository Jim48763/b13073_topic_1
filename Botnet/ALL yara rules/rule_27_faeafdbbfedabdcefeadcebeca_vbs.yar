rule faeafdbbfedabdcefeadcebeca_vbs {
strings:
        $s1 = "Latin = DFxnv"
        $s2 = "const ig = 16"
        $s3 = "VQVQp = Array(45,257,10,9,9,146,149,45,13,11,9,9,81,148,93,45,97,81,148,27,81,138,251,264,264,264,264,82,193,9,9,9,9,9,9,9,137,82,208,202,264,264,264,264,86,146,211,86,58,203,82,193,172,199,124,252,258,ig,99,227,86,58,202,85,18,219,86,18,202,81,138,251,264,264,264,264,85,42,211,81,140,259,9,74,24,158,204,74,137,236,10,77,145,165,45,168,9,9,9,148,14,227,100,9,9,148,22,217,100,9,9,146,207,138,207,161,246,103,223,140,247,10,138,247,161,246,103,223,24,184,207,140,233,10,140,257,9,74,24,157,204,140,258,19,24,165,204,77,145,232,73,137,256,264,73,145,230,73,137,254,264,74,191,10,74,137,255,9,74,145,264,74,137,240,9,78,41,252,74,145,245,74,137,237,9,77,41,252,78,17,232,74,17,229,78,57,240,73,17,248,73,137,256,264,74,137,215,9,77,41,256,74,17,264,74,255,208,10,193,106,168,20,212,194,100,89,57,236,24,78,209,146,85,45,53,242,199,17,9,9,147,141,45,168,9,9,9,177,10,194,9,143,19,104,195,227,24,117,145,24,78,218,146,93,45,53,242,168,17,9,9,81,148,141,45,145,9,9,9,146,141,45,253,10,9,9,81,148,85,45,97,81,148,18,81,208,203,264,264,264,264,81,138,251,264,264,9,9,82,146,209,82,58,217,82,42,209,85,146,77,45,65,81,148,85,45,65,81,146,149,45,241,10,9,9,81,148,149,45,241,10,9,9,146,149,45,249,10,9,9,208,77,45,53,249,142,221,ig,242,76,17,9,9,148,14,219,99,9,9,148,22,209,99,9,9,146,203,138,203,260,73,166,39,140,243,10,138,243,260,73,166,39,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,9,77,145,223,73,137,239,9,74,41,225,77,145,232,73,137,240,9,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,9,74,41,227,77,17,223,73,255,207,10,193,76,169,17,121,194,247,31,48,54,24,78,209,146,85,45,53,242,193,ig,9,9,58,201,146,202,81,148,157,45,145,9,9,9,146,157,45,237,10,9,9,85,148,141,45,145,9,9,9,85,148,85,45,97,86,148,18,82,146,211,86,50,203,82,146,209,86,50,209,86,10,203,85,50,218,81,146,85,45,57,81,148,85,45,73,81,146,149,45,225,10,9,9,81,148,149,45,225,10,9,9,146,149,45,233,10,9,9,85,148,77,45,57,82,138,201,11,9,9,9,85,146,77,45,65,85,148,77,45,65,85,146,141,45,209,10,9,9,85,148,141,45,209,10,9,9,77,146,141,45,221,10,9,9,148,14,204,98,9,9,148,22,194,98,9,9,146,203,138,243,158,192,159,155,140,243,10,138,203,158,192,159,155,24,184,203,140,233,10,140,257,9,74,24,157,204,140,258,19,24,165,204,77,145,231,73,41,231,74)"
        $s4 = "zGXe = Array(57,228,77,17,231,73,255,207,10,193,180,74,248,224,194,247,31,48,54,24,78,209,146,85,45,53,242,231,Zl,9,9,208,77,45,53,249,142,221,ig,242,218,Zl,9,9,81,148,141,45,145,9,9,9,146,141,45,205,10,9,9,81,148,22,21,98,9,9,81,148,93,45,65,85,148,77,45,89,81,146,85,45,41,85,146,202,85,148,77,45,41,74,264,217,81,146,77,45,81,81,148,77,45,81,146,141,45,189,10,9,9,81,140,133,45,81,9,193,154,119,135,175,74,194,155,111,215,243,77,24,78,209,77,146,85,45,53,242,122,Zl,9,9,208,77,45,53,213,90,115,91,242,109,Zl,9,9,148,14,252,97,9,9,148,22,242,97,9,9,146,203,138,243,244,167,124,252,140,243,10,138,203,244,167,124,252,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,173,89,72,110,194,206,215,247,76,24,78,209,146,85,45,53,242,22,Zl,9,9,81,148,141,45,145,9,9,9,146,141,45,185,10,9,9,81,148,85,45,81,81,148,93,45,73,81,146,19,81,148,85,45,73,81,146,149,45,169,10,9,9,81,148,149,45,169,10,9,9,146,149,45,181,10,9,9,81,148,93,45,97,81,138,203,17,9,9,9,81,146,93,45,97,81,148,93,45,97,81,146,157,45,153,10,9,9,81,148,157,45,153,10,9,9,146,157,45,165,10,9,9,85,148,77,45,73,82,138,201,17,9,9,9,85,146,77,45,73,85,148,77,45,73,85,146,141,45,137,10,9,9,85,148,141,45,137,10,9,9,77,146,141,45,149,10,9,9,148,14,18,97,9,9,148,22,264,96,9,9,146,203,138,243,182,171,29,173,140,243,10,138,203,182,171,29,173,24,184,203,140,233,10,140,257,9,74,24,157,202,140,258,19,74,24,165,203,78,145,212,78,41,220,78,57,218,78,17,212,74,255,204,10,193,10,118,213,244,194,206,215,247,76,24,78,209,146,85,45,53,242,44,14,9,9,208,77,45,53,108,248,151,214,242,31,14,9,9,148,14,174,96,9,9,148,22,164,96,9,9,146,203,138,203,252,26,46,140,140,243,10,138,243,252,26,46,140,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,9,77,145,223,73,137,239,9,74,41,225,77,145,232,73,137,240,9,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,9,74,41,227,77,17,223,73,255,207,10,193,236,82,94,130,194,173,18,50,100,24,78,209,146,85,45,53,242,148,13,9,9,58,201,81)"
        $s5 = "DiJQ = Array(65,10,9,9,146,141,45,77,10,9,9,208,77,45,13,34,66,157,192,242,225,Zl,9,9,58,201,146,202,81,148,93,45,65,85,148,77,45,33,86,148,17,81,50,218,82,50,210,86,146,17,81,148,85,45,33,81,146,149,45,49,10,9,9,81,148,149,45,49,10,9,9,146,149,45,61,10,9,9,208,77,45,13,34,66,157,192,242,158,Zl,9,9,81,148,77,45,33,148,17,140,250,264,195,264,264,264,264,74,146,217,74,138,249,264,264,264,12,74,146,218,74,138,250,251,158,115,73,77,18,202,74,138,210,251,158,115,73,140,250,264,77,42,210,140,258,11,74,24,155,203,74,137,235,10,74,24,191,211,146,85,45,25,81,148,77,45,65,148,85,45,25,138,242,54,88,103,89,10,202,138,202,54,88,103,89,146,85,45,25,85,148,101,45,33,85,146,165,45,33,10,9,9,85,148,165,45,33,10,9,9,77,146,165,45,45,10,9,9,81,148,125,45,33,148,Zl,146,218,138,250,9,9,9,261,74,146,201,74,58,209,74,42,201,148,77,45,25,202,257,11,146,218,138,250,264,264,264,12,74,146,202,74,58,210,74,42,202,77,146,201,140,249,264,77,146,210,140,250,264,138,251,34,50,154,59,74,146,204,74,138,236,34,50,154,59,74,42,217,146,216,138,240,34,50,154,59,74,42,218,78,18,204,77,18,216,74,58,260,18,209,140,249,264,138,211,34,50,154,59,42,217,74,18,204,81,148,125,45,33,77,146,39,81,148,125,45,33,81,146,189,45,17,10,9,9,81,148,189,45,17,10,9,9,146,189,45,29,10,9,9,208,77,45,13,34,66,157,192,242,124,14,9,9,81,148,77,45,33,81,146,141,45,257,9,9,9,81,148,141,45,257,9,9,9,146,141,45,13,10,9,9,208,77,45,13,34,66,157,192,242,83,14,9,9,81,148,77,45,33,81,146,141,45,241,9,9,9,81,148,141,45,241,9,9,9,146,141,45,253,9,9,9,208,77,45,13,34,66,157,192,242,42,14,9,9,58,201,148,22,142,46,9,9,148,30,132,46,9,9,140,241,10,74,146,209,74,10,201,74,24,184,209,140,234,10,140,258,9,74,24,157,202,140,259,19,74,24,165,203,78,145,212,78,41,220,78,57,218,78,17,212,74,255,204,10,193,116,121,127,88,194,126)"
        $s6 = "kjAnD = Array(81,146,85,45,33,81,148,85,45,33,81,146,149,45,153,11,9,9,81,148,149,45,153,11,9,9,146,149,45,165,11,9,9,85,148,85,45,57,74,24,192,18,202,258,21,146,85,45,81,208,77,45,13,184,252,93,72,242,34,31,9,9,148,77,45,81,140,257,14,193,164,133,36,28,194,208,173,35,184,24,85,209,146,85,45,13,242,261,30,9,9,148,77,45,81,140,257,ig,193,192,85,120,251,194,86,235,260,196,24,85,209,146,85,45,13,242,232,30,9,9,148,77,45,81,140,257,18,193,167,115,68,250,194,104,36,200,22,24,85,209,146,85,45,13,242,203,30,9,9,148,77,45,81,140,257,19,193,239,170,206,248,194,135,236,11,81,24,85,209,146,85,45,13,242,174,30,9,9,148,77,45,81,140,257,19,193,124,30,48,215,194,42,55,240,226,24,77,209,146,85,45,13,242,145,30,9,9,148,77,45,81,140,257,ig,193,202,136,218,151,194,42,55,240,226,24,77,209,146,85,45,13,242,116,30,9,9,148,77,45,81,140,257,Zl,193,10,96,129,246,194,228,91,78,229,24,85,209,146,85,45,13,242,87,30,9,9,148,77,45,81,140,257,11,193,156,27,144,174,194,18,24,172,249,24,85,209,146,85,45,13,242,58,30,9,9,148,77,45,81,140,257,12,193,230,83,198,125,194,115,37,133,167,24,85,209,146,85,45,13,242,29,30,9,9,148,77,45,81,140,257,13,193,40,260,65,203,194,237,253,208,164,24,85,209,146,85,45,13,242,256,29,9,9,148,77,45,81,140,257,10,193,223,152,245,230,194,236,120,148,10,24,85,209,146,85,45,13,242,227,29,9,9,148,77,45,81,140,257,9,193,206,259,112,96,194,42,55,240,226,24,77,209,146,85,45,13,242,198,29,9,9,58,201,81,148,85,45,65,81,148,93,45,33,77,148,11,50,209,74,50,201,77,146,11,81,148,93,45,33,81,146,157,45,137,11,9,9,81,148,157,45,137,11,9,9,146,157,45,149,11,9,9,208,77,45,13,34,66,157,192,242,134,29,9,9,148,14,236,61,9,9,148,22,226,61,9,9,146,203,138,203,95,242,196,134,140,243,10,138,243,95,242,196,134,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,10,77,145,223,73,137,239,264,74,41,225,77,145,232,73,137,240,264,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,10,74,41,227,77,17,223,73,255,207,10,193,190,137,185,95,194,94,62,45,115,24,78,209,146,85,45,13,242,251,28,9,9,58,201,81,148,85,45,33,24,192,26,140,259,25,74,24,165,201,74,137,233,10,74,24,191,217,146,93,45,25,81,148,85,45,65,148,93,45,25,138,203,44,50,169,107,10,211,138,243,44,50,169,107,146,93,45,25,148,85,45,25,202,258,25,85,148,85,45,33,111,74,146,18,85,148,85,45,33,85,146,149,45,121,11,9,9,85,148,149,45,121,11,9,9,77,146,149,45,133,11,9,9,148,30,252,60,9,9,77,148,22,241,60,9,9,140,241,10,74,146,219,74,10,203,74,24,184,219,140,235,10,140,259,9,74,24,157,201,74,140,258,19,74,24,165,204,77,145,204,77,41,228,78,57,225,77,17,204,255,204,10,193,254,42,150,99,195,94,62,45,115,24,78,217,146,93,45,13,242,69,28,9,9,208,77,45,13,34,66,157,192,242,56,28,9,9,24,192,77,45,31,194,264,264,264,264,140,250,11,146,203,58,211,42)"
        $s7 = "WQz = Array(24,165,203,78,145,212,74,137,252,264,77,145,220,137,252,264,73,191,10,73,137,255,10,77,145,232,73,137,240,264,74,41,250,73,145,230,73,137,238,264,74,41,251,77,17,216,77,17,222,73,57,248,74,17,228,74,137,252,264,73,137,215,10,74,41,252,77,17,232,73,255,208,10,193,113,87,64,261,194,54,200,71,184,24,78,209,146,85,45,65,242,131,17,9,9,81,148,77,45,121,81,146,141,45,97,10,9,9,81,148,141,45,97,10,9,9,146,141,45,105,10,9,9,137,133,45,116,9,24,158,202,137,234,10,145,149,45,152,9,9,9,148,14,108,76,9,9,148,30,98,76,9,9,74,146,201,74,138,201,146,119,234,260,74,140,241,10,74,138,241,146,119,234,260,74,24,184,201,140,233,10,140,257,9,24,157,202,140,259,19,74,24,165,202,74,145,211,78,41,211,77,57,210,74,17,211,74,255,203,10,193,209,203,79,101,195,54,200,71,184,24,78,217,146,93,45,65,242,250,ig,9,9,147,141,45,152,9,9,9,177,10,194,34,33,210,44,195,70,33,166,99,24,78,218,146,93,45,65,242,219,ig,9,9,137,197,45,89,11,9,9,9,193,148,190,162,106,194,110,229,264,99,24,78,209,146,85,45,65,242,189,ig,9,9,148,14,212,75,9,9,148,22,202,75,9,9,146,203,138,243,119,17,110,78,140,243,10,138,203,119,17,110,78,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,135,141,149,10,194,140,247,253,97,24,78,209,146,85,45,65,242,102,ig,9,9,148,77,45,85,146,202,81,146,149,45,153,9,9,9,148,14,111,75,9,9,148,30,101,75,9,9,74,146,201,74,138,241,81,121,70,202,74,140,241,10,74,138,201,81,121,70,202,74,24,184,201,140,233,10,140,257,9,74,24,157,202,140,259,19,74,24,165,203,78,145,212,74,137,252,264,77,145,220,137,252,264,73,191,10,73,137,255,9,77,145,232,73,137,240,9,74,41,250,73,145,230,73,137,238,9,74,41,251,77,17,216,77,17,222,73,57,248,74,17,228,74,137,252,264,73,137,215,9,74,41,252,77,17,232,73,255,208,10,193,48,153,202,73,195,140,247,253,97,24,78,217,146,93,45,65,242,198,Zl,9,9,208,77,45,65,181,100,192,264,81,148,141,45,153,9,9,9,81,146,77,45,57,242,172,Zl,9,9,81,148,77,45,105,148,85,45,85,146,211,81,10,217,208,77,45,65,181,100,192,264,81,146,77,45,57,242,140,Zl,9,9,81,148,77,45,57,81,146,77,45,129,208,77,45,65,243,174,152,250,242,117,Zl,9,9,148,14,140,74,9,9,148,22,130,74,9,9,146,203,138,203,40,121,136,237,140,243,10,138,243,40,121,136,237,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,10,77,145,223,73,137,239,264,74,41,225,77,145,232,73,137,240,264,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,10,74,41,227,77,17,223,73,255,207,10,193,148,69,108,222,194,158,229,133,263,24,78,209,146,85,45,65,242,234,14,9,9,81,148,77,45,105,81,146,141,45,81,10,9,9,81,148,141,45,81,10,9,9,146,141,45,93,10,9,9,148,14,229,73,9,9,148,22,219,73,9,9,146,203,138,243,96,44,129,99,140,243,10,138,203,96,44,129,99,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258)"
        $s8 = "End Function"
        $s9 = "Sko = Array(200,87,165,25,61,74,199,36,63,246,209,77,24,78,256,77,146,190,153,11,9,9,242,156,10,9,9,58,201,194,25,9,9,9,146,78,41,81,146,209,241,162,199,9,9,81,50,205,81,146,233,208,9,103,9,9,9,148,30,260,231,9,9,77,148,14,249,231,9,9,77,148,86,41,74,138,242,113,111,145,204,74,146,219,78,50,211,77,148,86,41,74,140,242,10,78,10,211,77,148,86,41,74,138,242,113,111,145,204,78,10,211,74,24,184,219,140,235,10,140,259,9,74,24,157,204,74,140,257,19,24,165,204,77,145,231,73,137,255,264,73,137,239,10,73,192,10,74,145,263,74,137,255,10,78,41,252,74,145,264,74,137,256,10,74,137,240,264,74,137,239,10,77,17,231,78,17,256,77,57,263,74,145,228,74,137,252,264,74,137,236,9,74,145,263,74,137,255,9,77,41,252,74,145,264,74,137,256,10,74,137,240,9,74,137,239,10,74,17,228,78,17,256,78,57,260,73,145,252,137,252,264,137,236,9,74,145,263,74,137,255,9,74,145,256,78,41,256,78,145,229,74,137,253,264,74,137,237,9,78,145,230,78,41,254,77,17,260,78,17,245,77,57,236,74,145,255,74,137,255,264,78,145,232,74,137,256,264,74,145,261,74,137,253,10,78,145,254,74,137,238,264,77,41,239,77,145,257,45,264,78,41,236,74,17,254,77,17,225,74,57,206,78,17,263,74,137,255,264,74,137,213,10,78,41,239,78,17,254,77,145,241,61,264,45,10,73,137,256,10,74,41,262,77,17,241,74,145,228,74,41,204,57,204,74,17,228,74,255,204,10,195,215,11,138,197,74,193,36,63,246,209,77,24,78,203,77,146,142,153,11,9,9,242,41,9,9,9,193,25,9,9,9,241,55,198,9,9,81,50,205,81,146,233,208,9,103,9,9,9,208,142,153,11,9,9,87,165,25,61,242,249,261,264,264,81,148,78,49,81,146,205,148,22,Zl,230,9,9,146,211,140,251,264,138,235,42,185,154,111,74,193,264,264,264,264,74,138,249,42,185,154,111,77,42,202,18,211,146,30,236,229,9,9,82,146,234,148,22,87,230,9,9,148,30,77,230,9,9,74,146,209,74,138,241,119,207,173,214,74,140,201,264,74,138,201,119,207,173,214,74,24,184,209,140,234,10,140,258,9,74,24,157,203,74,137,235,10,77,145,158,151,11,9,9,140,259,19,74,24,165,203,74,137,235,10,77,145,158,152,11,9,9)"
        $s10 = "IIbl = Array(9,9,86,10,209,74,148,81,21,74,146,209,85,10,203,81,146,93,45,113,81,148,157,45,153,9,9,9,81,146,157,45,65,12,9,9,81,148,157,45,65,12,9,9,146,157,45,73,12,9,9,85,148,77,45,129,24,192,85,45,103,74,146,210,86,114,210,49,9,9,9,86,10,209,74,148,81,17,146,85,45,121,85,148,141,45,153,9,9,9,85,146,141,45,49,12,9,9,85,148,141,45,49,12,9,9,77,146,141,45,61,12,9,9,208,77,45,125,9,9,9,9,148,22,170,152,9,9,148,30,160,152,9,9,140,241,10,74,146,209,74,10,201,74,24,184,209,140,234,10,140,258,9,74,24,157,203,140,259,19,74,24,165,204,77,145,220,137,252,264,77,145,231,73,137,255,264,73,192,10,73,137,256,10,73,145,230,73,137,238,264,74,41,259,74,145,255,74,137,239,264,74,41,260,77,17,222,78,17,231,77,57,254,73,17,252,137,252,264,73,137,216,10,73,41,260,73,17,230,73,255,206,10,193,ig,249,221,102,194,108,99,43,111,24,78,209,146,85,45,65,242,246,23,9,9,208,77,45,65,240,86,224,87,242,233,23,9,9,148,77,45,125,68,77,45,121,193,82,215,250,130,194,260,202,251,111,24,75,209,146,85,45,65,242,203,23,9,9,148,14,250,151,9,9,148,22,240,151,9,9,146,203,138,203,109,185,186,38,140,243,10,138,243,109,185,186,38,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,10,77,145,223,73,137,239,264,74,41,225,77,145,232,73,137,240,264,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,10,74,41,227,77,17,223,73,255,207,10,193,191,239,62,159,194,243,20,164,35,24,78,209,146,85,45,65,242,64,23,9,9,81,148,141,45,153,9,9,9,81,146,141,45,33,12,9,9,81,148,141,45,33,12,9,9,146,141,45,45,12,9,9,81,148,85,45,113,207,10,9,81,148,149,45,153,9,9,9,81,146,149,45,17,12,9,9,81,148,149,45,17,12,9,9,146,149,45,29,12,9,9,81,148,93,45,113,81,138,203,10,9,9,9,81,146,93,45,113,81,148,157,45,153,9,9,9,81,146,157,45,257,11,9,9,81,148,157,45,257,11,9,9,146,157,45,13,12,9,9,148,14,249,150,9,9,148,22,239,150,9,9,146,203,138,243,19,127,133,235,140,243,10,138,203,19,127,133,235,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,9,77,145,223,73,137,239,9,74,41,225,77,145,232,73,137,240,9,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,9,74,41,227,77,17,223,73,255,207,10,193,238,79,Zl,209,194,243,20,164,35,24,78)"
        $s11 = "dTnDX = Array(74,140,258,19,74,24,165,204,77,145,204,137,252,264,77,145,231,73,137,255,264,73,192,10,73,137,256,9,74,145,231,74,137,239,9,74,41,257,74,145,256,74,137,240,9,74,41,260,78,17,207,78,17,232,78,57,263,73,17,252,137,252,264,73,137,216,9,73,41,260,74,17,231,74,255,207,10,193,234,39,189,132,74,194,194,42,149,128,77,24,78,209,77,146,86,201,242,106,13,9,9,147,78,248,177,10,194,233,91,159,263,195,48,44,94,44,24,78,218,146,94,201,242,80,13,9,9,81,148,78,225,81,148,9,81,146,78,97,81,148,78,97,146,78,109,81,148,86,217,81,148,18,81,148,94,225,81,148,27,81,108,91,69,81,10,218,81,148,94,233,81,146,19,81,148,86,233,81,148,18,81,146,86,81,81,148,86,81,146,86,93,81,148,94,233,81,148,27,138,67,89,78,9,9,193,226,117,112,88,194,210,212,219,142,24,77,209,146,86,201,242,238,12,9,9,81,148,78,217,81,148,9,81,146,78,65,81,148,78,65,146,78,77,81,148,86,233,81,148,18,81,148,94,209,81,146,19,208,78,201,197,196,100,93,242,194,12,9,9,148,14,117,133,9,9,148,22,107,133,9,9,146,203,138,203,31,220,48,233,140,243,10,138,243,31,220,48,233,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,113,157,73,169,194,30,243,194,93,24,78,209,146,86,201,242,108,12,9,9,148,14,31,133,9,9,148,22,21,133,9,9,146,203,138,203,231,109,206,69,140,243,10,138,243,231,109,206,69,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,59,172,101,60,194,30,243,194,93,24,78,209,146,86,201,242,22,12,9,9,208,78,201,48,44,94,44,242,10,12,9,9,148,14,189,132,9,9,148,22,179,132,9,9,146,203,138,203,53,237,229,85,140,243,10,138,243,53,237,229,85,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,40,101,253,232,194,251,70,255,218,24,78,209,146,86,201,242,180,11,9,9,58,201,81,148,86,217,81,148,18,81,146,86,49,81,148,86,49,146,86,61,81,148,94,209,81,208,11,9,9,9,9,148,22,72,132,9,9,77,148,14,61,132,9,9,140,241,10,74,146,210,74,10,202,74,24,184,210,140,234,10,140,258,9,74,24,157,203,74,140,257,19,74,24,165,204,77,145,220,137,252,264,77,145,231,73,137,255,264,73,192,10,73,137,256,9,74,145,231,74,137,239,9,74,41,259,74,145,256,74,137,240,9,74,41,260,78,17,223,78,17,232,78,57,263,73,17,252,137,252,264,73,137,216,9,73,41,260,74,17,231,74,255,207,10,193,220,114,167,193)"
        $s12 = "RjXC = Array(77,145,228,137,252,264,74,145,256,74,41,232,78,17,263,73,145,252,137,252,264,78,145,232,74,137,256,264,74,145,261,74,137,253,10,74,145,230,74,137,238,264,77,41,239,77,145,257,45,264,78,41,236,74,17,254,77,17,225,74,57,206,77,17,260,137,252,264,74,137,213,10,77,41,236,74,17,230,77,145,241,61,264,45,10,73,137,256,10,74,41,262,77,17,241,78,145,252,74,41,204,74,57,207,78,17,252,74,255,204,10,195,215,11,138,197,74,193,36,63,246,209,77,24,78,203,77,146,142,17,12,9,9,242,41,9,9,9,193,25,9,9,9,241,18,252,9,9,81,50,205,81,146,233,208,9,103,9,9,9,208,142,17,12,9,9,87,165,25,61,242,14,262,264,264,81,148,142,89,10,9,9,81,146,205,148,22,99,28,10,9,148,30,89,28,10,9,74,146,209,74,138,241,32,35,31,206,74,140,241,10,74,138,201,32,35,31,206,74,24,184,209,140,234,10,140,258,9,74,24,157,202,140,259,19,74,24,165,203,78,145,212,74,137,252,264,77,145,220,137,252,264,73,191,10,73,137,255,10,77,145,232,73,137,240,264,74,41,250,74,145,231,74,137,239,264,74,41,251,77,17,216,78,17,223,77,57,256,74,17,228,74,137,252,264,73,137,215,10,74,41,252,77,17,232,73,255,208,10,194,94,132,103,35,195,179,ig,204,68,24,78,218,146,158,9,11,9,9,242,17,93,9,9,208,142,9,11,9,9,155,254,166,252,242,258,92,9,9,81,148,142,25,11,9,9,81,148,9,147,17,81,148,142,33,11,9,9,145,17,81,146,233,148,30,160,27,10,9,77,148,14,149,27,10,9,74,146,218,74,138,242,200,228,106,210,74,140,202,264,74,138,202,200,228,106,210,74,24,184,218,140,235,10,140,259,9,24,157,202,137,234,10,145,150,Zl,12,9,9,74,140,257,19,24,165,202,137,234,10,145,150,ig,12,9,9,208,142,9,12,9,9,104,60,180,254,81,146,142,73,10,9,9,148,142,9,12,9,9,146,202,138,242,215,11,138,197,146,142,69,10,9,9,24,141,213,11,9,9,242,9,9,9,9,148,142,69,10,9,9,54,36,63,246,209,24,141,154,11,9,9,242,9,9,9,9,148,142,69,10,9,9,54,104,60,180,254,24,141,41,9,9,9,242,9,9,9,9,148,142,69,10,9,9,54,87,165,25,61,24,141,202,9,9,9,242,9,9,9,9,242,132,11,9,9,147,142,Zl,12,9,9,147,150,ig,12,9,9,145,203,137,251,264,137,235,10,74,185,10,78,145,202,74,137,250,10,77,41,209,78,145,203,74,137,251,10,74,137,235,264,74,137,234,10,17,203,78,17,211,77,57,219,145,209,61,264,45,10,78,145,202,74,137,250,10,77,41,210,78,145,203,74,137,251,10,74,137,235,264,74,137,234,10,17,209,78,17,211,77,57,217,145,218,137,250,264,74,145,202,74,41)"
        $s13 = "EWm = Array(45,41,9,9,9,9,146,77,45,53,241,65,43,9,9,81,146,77,45,73,81,148,77,45,113,81,146,141,45,145,10,9,9,81,148,141,45,145,10,9,9,146,141,45,157,10,9,9,81,140,133,45,73,9,193,60,161,212,103,195,255,145,91,223,24,78,217,146,93,45,61,242,123,ig,9,9,140,133,45,105,9,193,220,176,206,203,194,255,145,91,223,24,78,209,146,85,45,61,242,96,ig,9,9,148,77,45,105,146,141,45,141,10,9,9,81,148,85,45,65,24,192,74,31,140,249,264,195,264,264,264,264,74,146,217,74,140,249,10,138,251,231,52,80,52,77,18,201,138,211,231,52,80,52,140,249,264,42,217,140,257,9,193,37,59,67,114,195,163,209,Zl,251,24,78,217,146,93,45,61,242,ig,ig,9,9,148,77,45,105,146,141,45,137,10,9,9,207,77,45,112,9,81,148,85,45,113,81,146,149,45,121,10,9,9,81,148,149,45,121,10,9,9,146,149,45,133,10,9,9,208,77,45,61,126,84,137,71,242,215,Zl,9,9,81,148,77,45,113,81,146,141,45,105,10,9,9,81,148,141,45,105,10,9,9,146,141,45,117,10,9,9,207,77,45,112,10,81,148,85,45,113,81,146,149,45,89,10,9,9,81,148,149,45,89,10,9,9,146,149,45,101,10,9,9,208,77,45,61,126,84,137,71,242,141,Zl,9,9,148,77,45,105,146,141,45,85,10,9,9,208,77,45,61,259,200,234,213,242,117,Zl,9,9,81,148,77,45,113,81,146,141,45,73,10,9,9,81,148,141,45,73,10,9,9,146,141,45,81,10,9,9,208,77,45,61,91,165,194,244,242,76,Zl,9,9,148,14,67,124,9,9,148,22,57,124,9,9,146,203,138,243,257,165,100,256,140,243,10,138,203,257,165,100,256,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,138,68,146,48,194,149,247,36,218,24,78,209,146,85,45,61,242,245,14,9,9,140,133,45,105,9,24,158,201,45,10,145,141,45,143,9,9,9,148,22,219,123,9,9,148,30,209,123,9,9,74,146,209,74,138,241,200,166,86,59,74,140,241,10,74,138,201,200,166,86,59,74,24,184,209,140,234,10,140,258,9,24,157,201,140,259,19,74,24,165,202,74,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,10,77,145,223,73,137,239,264,41,225,77,145,232,73,137,240,264,74,41,226,73,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,10,74,41,227,77,17,223,73,255,207,10,194,37,216,182,155,195,149,247,36,218,24,78,218,146,93,45,61,242,86,14,9,9,147,141,45,143,9,9,9,177,10,194,244,197,184,80,195,49,Zl,45,253,24,78,218,146,93,45,61,242,55,14,9,9,58,201,146,202,148,77,45,105,146,141,45,69,10,9,9,81,148,93,45,73,148,75,13,146,77,45,93,148,77,45,93,146,141,45,65,10,9,9,148,77,45,93,77,148,77,45,105,74,138,201,233,257,114,260,74,50,201,74,138,241,233,257,114,260,77,146,77,45,105,148,77,45,105,146,141,45,61,10,9,9,148,77,45,93,146,203,81,138,242,17,9,9,9,81,10,211,146,93,45,93,148,77,45,93,146,141,45,57,10,9,9,148,77,45,93,146,202,81,202,242,10,146,85,45,93,148,77,45,93,146,141,45,53,10,9,9,85,148,85,45,73,82,138,202,17,9,9,9,85,146,85,45,81,85,148,85,45,81,85,146,149,45,41,10,9,9,85,148,149,45,41,10,9,9,77,146,149,45,49,10,9,9,85,148,93,45,113,85,148,101,45,73,74,148,12,74,146,204,81,199,207,169,113,10,101,13,166,226,82,50,251,86,10,227,82,10,251,85,146,93,45,97,85,148,93,45,97,77,146,157,45,37,10,9,9,85,148,85,45,121,85,148,77,45,81,148,93,45,93,81,148,85,45,97,241,29,63,9,9,81,146,77,45,73,81,148,77,45,97,146,141,45,21,10,9,9,81,140,133,45,73,9,193,109,115,191,240,195,196,18,186,158,24,78,217,146,93,45,61,242,263,12,9,9,148,14,254,121,9,9,148,22,244,121,9,9,146,203,138)"
        $s14 = "DkYbf = Array(209,146,85,45,65,242,63,22,9,9,208,77,45,65,246,194,237,110,242,50,22,9,9,148,14,97,150,9,9,148,22,87,150,9,9,146,203,138,203,246,250,65,57,140,243,10,138,243,246,250,65,57,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,10,77,145,223,73,137,239,264,74,41,225,77,145,232,73,137,240,264,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,10,74,41,227,77,17,223,73,255,207,10,193,91,40,104,31,194,70,206,86,121,24,78,209,146,85,45,65,242,167,21,9,9,58,201,148,85,45,125,146,203,50,211,146,202,140,242,10,10,211,146,202,50,218,146,85,45,125,148,22,189,149,9,9,148,30,179,149,9,9,140,241,10,74,146,209,74,10,201,74,24,184,209,140,234,10,140,258,9,74,24,157,202,140,259,19,74,24,165,203,78,145,212,78,41,220,78,57,218,78,17,212,74,255,204,10,193,40,85,50,129,194,70,206,86,121,24,78,209,146,85,45,65,242,62,21,9,9,208,77,45,65,240,86,224,87,242,49,21,9,9,148,14,96,149,9,9,148,22,86,149,9,9,146,203,138,203,208,101,43,249,140,243,10,138,243,208,101,43,249,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,162,145,103,60,194,17,91,222,37,24,78,209,146,85,45,65,242,218,20,9,9,24,192,77,45,103,146,141,45,253,11,9,9,81,148,85,45,129,24,192,77,45,103,146,203,81,114,219,49,9,9,9,81,10,218,148,74,25,146,77,45,97,81,148,149,45,153,9,9,9,81,146,149,45,241,11,9,9,81,148,149,45,241,11,9,9,146,149,45,249,11,9,9,81,148,157,45,153,9,9,9,85,148,77,45,129,24,192,77,45,103,74,146,202,86,114,210,49,9,9,9,86,10,209,74,148,73,21,74,146,201,85,10,203,81,146,93,45,89,81,148,157,45,153,9,9,9,81,146,157,45,225,11,9,9,81,148,157,45,225,11,9,9,146,157,45,237,11,9,9,85,148,141,45,177,9,9,9,85,148,85,45,129,24,192,77,45,103,74,146,203,86,114,219,49,9,9,9,86,10,218,74,148,74,29,74,146,202,86,10,209,85,146,77,45,81,85,148,141,45,153,9,9,9,85,146,141,45,209,11,9,9,85,148,141,45,209,11,9,9,77,146,141,45,221,11,9,9,208,77,45,125,9,9,9,9,148,14,30,148,9,9,148,22,20,148,9,9,146,203,138,203,256,34,158,20,140,243,10,138,243,256,34,158,20,24,184,203,140,233,10,140,257,9,74,24,157,204,140,258,19,24,165,204,77,145,231,73,137,255,264,73,145,232,73,137,256,264,73,190,10,73,137,254)"
        $s15 = "GULGj = Array(9,9,148,22,74,116,9,9,146,203,138,243,223,90,174,190,140,243,10,138,203,223,90,174,190,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,10,77,145,223,73,137,239,264,74,41,225,77,145,232,73,137,240,264,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,10,74,41,227,77,17,223,73,255,207,10,193,31,225,103,56,194,38,105,99,255,24,78,209,146,85,45,53,242,251,10,9,9,58,201,81,148,85,45,57,81,148,82,57,81,146,85,45,65,148,30,185,115,9,9,77,148,14,174,115,9,9,140,241,10,74,146,218,74,10,202,74,24,184,218,140,235,10,140,259,9,74,24,157,203,74,140,257,19,74,24,165,204,77,145,220,77,41,228,78,57,227,77,17,220,255,204,10,193,222,160,246,253,195,38,105,99,255,24,78,217,146,93,45,53,242,154,10,9,9,208,77,45,53,170,22,231,228,242,141,10,9,9,81,148,77,45,57,81,146,141,45,137,9,9,9,81,148,141,45,137,9,9,9,146,141,45,149,9,9,9,81,148,85,45,57,24,192,74,13,70,85,10,9,9,193,115,89,240,ig,195,175,10,104,104,24,77,217,146,93,45,53,242,77,10,9,9,148,14,27,115,9,9,148,22,17,115,9,9,146,203,138,203,20,145,152,224,140,243,10,138,243,20,145,152,224,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,240,208,136,46,194,124,189,98,33,24,78,209,146,85,45,53,242,246,9,9,9,81,148,77,45,57,148,81,61,146,209,81,146,77,45,65,148,22,181,114,9,9,148,30,171,114,9,9,74,146,209,74,138,201,256,156,232,181,74,140,241,10,74,138,241,256,156,232,181,74,24,184,209,140,234,10,140,258,9,74,24,157,202,140,259,19,74,24,165,203,78,145,212,78,41,220,78,57,218,78,17,212,74,255,204,10,194,64,35,22,150,195,124,189,98,33,24,78,218,146,93,45,53,242,139,9,9,9,208,77,45,53,175,10,104,104,242,126,9,9,9,81,148,77,45,57,81,146,77,45,121,81,148,77,45,121,146,77,45,133,208,77,45,53,74,170,197,189,242,94,9,9,9,81,148,77,45,73,81,146,77,45,105,81,148,77,45,105,146,77,45,117,81,148,77,45,65,81,138,205,169,9,9,9,100,104,103,204,81,148,77,45,57,81,148,73,57,81,146,77,45,65,208,77,45,53,31,225,103,56,242,32,9,9,9,81,148,77,45,57,148,81,61,146,209,81,146,77,45,65,208,77,45,53,240,208,136,46,242,24,261,264,264,213,213,213,74,96,74,95,74,93,95,96,94,92,81,138,245,169,11,9,9,58,201,146,203,81,146,149,45,145,9,9,9,208,141,45,141,9,9,9,9,9,9,9,81,148,149,45,145,9,9,9,146,149,45,169,9,9,9,85,148,141,45,145,9,9,9,85,148,149,45,145,9,9,9,86,108,82,69,82,146,219,86,50,203,82,146,217,86,50,209,86,10,203,85,50,219,81,146,93,45,129,81,148,157,45,145,9,9,9,146,157,45,93,10,9,9,208,77,45,125,9,9,9,9,85,148,77,45,129,85,146,141,45,193,10,9,9,85,148,141,45,193,10,9,9,77,146,141,45,201,10,9,9,85,148,85,45,129,74,148,138,157,9,9)"
        $s16 = "cPLzy = Array(9,81,148,77,45,73,81,138,205,177,11,9,9,100,102,104,103,74,101,74,102,74,103,74,104,204,81,148,77,45,33,24,192,17,140,258,25,24,165,203,137,235,10,24,191,211,146,85,45,25,81,148,77,45,65,148,85,45,25,138,242,39,96,40,226,10,202,138,202,39,96,40,226,146,85,45,25,148,77,45,25,202,257,25,85,148,77,45,33,111,74,146,9,85,148,77,45,33,85,146,141,45,161,9,9,9,85,148,141,45,161,9,9,9,77,146,141,45,173,9,9,9,208,77,45,13,190,137,185,95,242,100,10,9,9,58,201,81,148,85,45,33,24,192,26,140,259,25,74,24,165,201,74,137,233,10,74,24,191,217,146,93,45,25,81,148,85,45,57,81,138,202,11,9,9,9,81,146,85,45,57,148,93,45,53,138,203,88,211,188,211,140,203,264,138,243,88,211,188,211,146,93,45,53,148,93,45,53,146,157,45,157,9,9,9,81,148,85,45,57,24,200,26,77,148,85,45,25,74,146,203,78,50,211,74,146,202,74,50,218,78,10,211,146,203,77,50,219,146,93,45,25,81,148,85,45,65,148,93,45,25,50,209,50,203,146,93,45,25,148,77,45,25,146,141,45,153,9,9,9,148,77,45,25,14,189,32,154,37,14,9,137,9,9,54,189,32,154,37,146,77,45,25,148,77,45,25,146,141,45,149,9,9,9,148,77,45,25,202,257,25,85,148,101,45,33,111,74,146,12,85,148,101,45,33,85,146,165,45,137,9,9,9,85,148,165,45,137,9,9,9,77,146,165,45,145,9,9,9,208,77,45,13,151,190,152,129,242,119,9,9,9,81,148,77,45,33,81,146,77,45,121,81,148,77,45,121,146,77,45,133,208,77,45,13,116,121,127,88,242,87,9,9,9,81,148,77,45,33,81,146,77,45,105,81,148,77,45,105,146,77,45,117,81,208,77,45,73,9,9,9,9,208,77,45,13,212,155,250,68,242,46,9,9,9,81,148,77,45,57,81,146,77,45,89,81,148,77,45,89,146,77,45,101,81,148,85,45,57,81,146,85,45,73,208,77,45,13,138,209,19,113,242,163,238,264,264,213,213,213,213,213,213,213,213,213,111,111,24,40,141,9,9,9,9,9,81,140,245,25,85,146,29,45,85,146,101,45,17,86,60,228,85,150,93,45,33,85,52,217,86,24,75,220,110,85,148,37,46,25,9,9,9,86,68,220,251,124,32,111,74,138)"
        $s17 = "fuhN = Array(140,235,10,140,259,9,74,24,157,203,74,137,235,10,77,145,158,167,11,9,9,74,140,257,19,74,24,165,203,74,137,235,10,77,145,158,168,11,9,9,208,142,161,11,9,9,104,60,180,254,81,146,86,121,148,142,161,11,9,9,146,202,138,242,215,11,138,197,146,78,117,24,141,125,11,9,9,242,9,9,9,9,148,78,117,54,36,63,246,209,24,141,69,11,9,9,242,9,9,9,9,148,78,117,54,104,60,180,254,24,141,38,9,9,9,242,9,9,9,9,148,78,117,54,87,165,25,61,24,141,223,9,9,9,242,9,9,9,9,242,53,11,9,9,147,142,167,11,9,9,147,150,168,11,9,9,145,203,137,251,264,137,235,9,74,185,10,78,145,202,74,137,250,9,77,41,209,78,145,203,74,137,251,10,74,137,235,9,74,137,234,10,17,203,78,17,211,77,57,219,145,209,61,264,45,10,78,145,202,74,137,250,10,77,41,210,78,145,203,74,137,251,10,74,137,235,264,74,137,234,10,17,209,78,17,211,77,57,217,145,218,137,250,264,137,234,9,78,145,202,74,137,250,9,74,145,219,78,41,211,74,145,204,74,137,252,264,74,137,236,9,145,204,77,41,212,77,17,218,74,17,228,77,57,226,74,145,218,74,41,202,57,203,74,17,218,77,145,209,61,264,45,10,74,137,249,10,78,41,202,77,17,209,145,211,41,203,57,202,17,211,255,203,10,199,87,165,25,61,200,36,63,246,209,24,78,263,146,198,161,11,9,9,242,105,10,9,9,58,201,194,25,9,9,9,146,78,113,81,146,209,241,64,204,9,9,81,50,205,81,146,233,208,9,Zl,11,9,9,148,30,162,236,9,9,77,148,14,151,236,9,9,77,148,86,113,74,50,218,77,148,94,113,74,138,243,113,111,145,204,78,10,218,77,148,94,113,78,50,211,74,138,203,33,181,155,199,74,140,243,10,74,138,243,33,181,155,199,77,148,86,113,74,138,242,113,111,145,204,78,10,211,74,24,184,219,140,235,10,140,259,9,74,24,157,204,74,140,257,19,24,165,204,77,145,231,73,137,255,264,73,137,239,10,73,192,10,74,145,263,74,137,255,10,78,41,252,74,145,264,74,137,256,10,74,137,240,264,74,137,239,10,77,17,231,78,17,256,77,57,263)"
        $s18 = "XRMFE = Array(23,9,9,148,77,45,85,146,141,45,165,10,9,9,208,77,45,65,33,48,25,158,242,92,23,9,9,208,77,45,65,149,145,202,122,242,79,23,9,9,81,148,77,45,97,24,192,81,13,138,258,109,143,9,9,194,45,90,39,92,195,159,134,226,234,24,77,218,146,93,45,65,242,42,23,9,9,58,201,148,22,63,82,9,9,148,30,53,82,9,9,140,241,10,74,146,209,74,10,201,74,24,184,209,140,234,10,140,258,9,74,24,157,202,140,259,19,74,24,165,203,78,145,212,78,41,220,78,57,218,78,17,212,74,255,204,10,193,53,213,145,248,194,163,103,221,262,24,78,209,146,85,45,65,242,216,22,9,9,81,148,77,45,105,81,146,141,45,153,10,9,9,81,148,141,45,153,10,9,9,146,141,45,161,10,9,9,81,148,85,45,97,81,146,85,45,89,81,148,85,45,105,81,146,149,45,137,10,9,9,81,148,149,45,137,10,9,9,146,149,45,149,10,9,9,81,148,93,45,89,148,77,45,117,74,146,201,75,140,197,203,145,9,9,9,9,74,24,158,202,74,137,234,10,77,145,149,45,150,9,9,9,148,14,136,81,9,9,148,22,126,81,9,9,74,146,203,74,138,203,131,92,127,228,74,140,243,10,74,138,243,131,92,127,228,74,24,184,203,140,233,10,140,257,9,74,24,157,202,140,258,19,74,24,165,204,77,145,212,77,41,228,78,57,226,77,17,212,255,204,10,193,84,183,67,230,194,163,103,221,262,24,78,209,146,85,45,65,242,22,22,9,9,147,141,45,150,9,9,9,177,10,194,233,31,185,87,195,32,196,237,68,24,78,218,146,93,45,65,242,247,21,9,9,81,148,77,45,105,81,146,141,45,121,10,9,9,81,148,141,45,121,10,9,9,146,141,45,133,10,9,9,148,77,45,117,81,148,85,45,89,68,138,141,9,9,9,193,184,43,244,71,195,257,210,145,26,24,76,217,146,93,45,65,242,182,21,9,9,148,14,205,80,9,9,148,22,195,80,9,9,146,203,138,203,116,72,108,184,140,243,10,138,243,116,72,108,184,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,245,231,22,209,194,134,141,128,149,24,78,209,146,85,45,65,242,95,21,9,9)"
        $s19 = "aTD = Array(19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,9,77,145,223,73,137,239,9,74,41,225,77,145,232,73,137,240,9,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,9,74,41,227,77,17,223,73,255,207,10,193,227,218,160,84,194,158,229,133,263,24,78,209,146,85,45,65,242,67,14,9,9,208,77,45,65,32,196,237,68,242,54,14,9,9,208,77,45,65,159,134,226,234,242,41,14,9,9,208,77,45,65,149,145,202,122,242,28,14,9,9,208,77,45,65,189,194,226,14,242,Zl,14,9,9,148,14,38,73,9,9,148,22,28,73,9,9,146,203,138,203,112,246,164,217,140,243,10,138,243,112,246,164,217,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,78,41,211,78,57,209,78,17,203,74,255,203,10,193,122,245,195,95,194,212,23,222,102,24,78,209,146,85,45,65,242,184,13,9,9,148,77,45,85,146,141,45,77,10,9,9,140,133,45,85,9,24,158,202,137,234,10,145,149,45,168,9,9,9,148,14,178,72,9,9,148,30,168,72,9,9,74,146,201,74,138,201,217,85,201,148,74,140,241,10,74,138,241,217,85,201,148,74,24,184,201,140,233,10,140,257,9,24,157,202,140,259,19,74,24,165,202,74,145,211,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,10,77,145,223,73,137,239,264,41,226,77,145,232,73,137,240,264,74,41,226,73,17,215,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,10,74,41,227,77,17,223,73,255,207,10,193,230,90,151,141,195,212,23,222,102,24,78,217,146,93,45,65,242,13,13,9,9,147,141,45,168,9,9,9,177,10,194,104,110,220,45,195,159,50,78,91,24,78,218,146,93,45,65,242,238,12,9,9,58,201,146,202,81,146,211,81,138,203,33,9,9,9,85,108,203,85,148,85,45,105,85,146,149,45,65,10,9,9,85,148,149,45,65,10,9,9,77,146,149,45,73,10,9,9,85,148,93,45,97,82,146,212,86,50,204,86,50,227,85,148,77,45,97,74,24,192,73,29,74,146,201,85,50,202,82,50,211,85,146,93,45,73,81,148,85,45,97,24,192,74,Zl,146,77,45,69,148,77,45,69,146,141,45,61,10,9,9,208,77,45,65,85,177,244,114,242,117,12,9,9,148,77,45,69,146,202,138,202,233,257,202,252,140,202,264,138,242,233,257,202,252,146,85,45,69,140,257,9,193,110,176,174,75,194,95,27,244,178,24,78,209,146,85,45,65,242,67,12,9,9,148,77,45,69,146,141,45,57,10,9,9,81,148,85,45,73,148,74,21,68,77,45,85,193,65,227,11,48,195,155,183,40,224,24,77,217,146,93,45,65,242,22,12,9,9,58,201,148,22,43,71,9,9,148,30,33,71,9,9,140,241,10,74,146,209,74,10,201,74,24,184,209,140,234,10,140,258,9,74,24,157,202,140,259,19,74,24,165,203,78,145,212,74,137,252,264,77,145,220,137,252,264,73,191,10,73,137,255,9,77,145,232,73,137,240,9,74,41,250,73,145,230,73,137,238,9,74,41,251,77,17,216,77,17,222,73,57,248,74,17,228,74,137,252,264,73,137,215,9,74,41,252,77,17,232,73,255,208,10,193,205,195)"
        $s20 = "fzKj = Array(9,9,81,148,141,45,177,9,9,9,81,146,141,45,257,10,9,9,81,148,141,45,257,10,9,9,146,141,45,13,11,9,9,148,14,221,143,9,9,148,22,211,143,9,9,146,203,138,203,124,9,172,252,140,243,10,138,243,124,9,172,252,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,10,77,145,223,73,137,239,264,74,41,225,77,145,232,73,137,240,264,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,10,74,41,227,77,17,223,73,255,207,10,193,131,128,173,12,194,39,206,155,84,24,78,209,146,85,45,65,242,35,Zl,9,9,208,77,45,65,157,87,97,21,242,22,Zl,9,9,148,14,69,143,9,9,148,22,59,143,9,9,146,203,138,243,38,122,202,184,140,243,10,138,203,38,122,202,184,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,9,77,145,223,73,137,239,9,74,41,225,77,145,232,73,137,240,9,74,41,226,77,17,207,77,17,216,73,57,263,78,17,227,74,137,251,264,137,212,9,74,41,227,77,17,223,73,255,207,10,193,183,89,202,187,194,119,261,231,170,24,78,209,146,85,45,65,242,139,14,9,9,58,201,81,148,149,45,177,9,9,9,81,146,149,45,241,10,9,9,81,148,149,45,241,10,9,9,146,149,45,253,10,9,9,208,141,45,173,9,9,9,11,9,9,9,81,148,157,45,177,9,9,9,81,146,157,45,225,10,9,9,81,148,157,45,225,10,9,9,146,157,45,237,10,9,9,148,22,111,142,9,9,148,30,101,142,9,9,140,241,10,74,146,209,74,10,201,74,24,184,209,140,234,10,140,258,9,74,24,157,202,140,259,19,74,24,165,203,78,145,212,78,41,220,78,57,218,78,17,212,74,255,204,10,193,27,115,11,90,194,119,261,231,170,24,78,209,146,85,45,65,242,240,13,9,9,208,77,45,65,157,87,97,21,242,227,13,9,9,148,14,18,142,9,9,148,22,264,141,9,9,146,203,138,203,67,128,26,71,140,243,10,138,243,67,128,26,71,24,184,203,140,233,10,140,257,9,74,24,157,201,140,258,19,74,24,165,202,78,145,203,74,137,251,264,78,145,212,74,137,252,264,188,10,137,252,9,77,145,223)"
condition:
    uint16(0) == 0x5a4d and filesize < 463KB and
    4 of them
}
    
