module SVTYPE;

export {
    # 4 bayttan LE 32-bit mask üret + bayrakları decode et
    global decode_from_bytes: function(b1: int, b2: int, b3: int, b4: int): set[string];
    global join:              function(names: set[string], sep: string): string;
}

# --- Tek sözlük: flag -> okunur ad ---
const FLAGS: table[count] of string = {
    [0x00000001] = "Workstation",
    [0x00000002] = "Server",
    [0x00000004] = "SQL",
    [0x00000008] = "Domain Controller",
    [0x00000010] = "Backup Controller",
    [0x00000020] = "Time Source",
    [0x00000040] = "Apple",
    [0x00000080] = "Novell",
    [0x00000100] = "Member",
    [0x00000200] = "Print",
    [0x00000400] = "Dialin",
    [0x00000800] = "Xenix",
    [0x00001000] = "NT Workstation",
    [0x00002000] = "WfW",
    [0x00008000] = "NT Server",
    [0x00010000] = "Potential Browser",
    [0x00020000] = "Backup Browser",
    [0x00040000] = "Master Browser",
    [0x00080000] = "Domain Master Browser",
    [0x00100000] = "OSF",
    [0x00200000] = "VMS",
    [0x00400000] = "Windows 95+",
    [0x00800000] = "DFS",
    [0x40000000] = "Local",
    [0x80000000] = "Domain Enum",
};

# Little-endian: mask = b1 + b2*256 + b3*65536 + b4*16777216
function decode_from_bytes(b1: int, b2: int, b3: int, b4: int): set[string]
    {
    local c1 = int_to_count(b1);
    local c2 = int_to_count(b2);
    local c3 = int_to_count(b3);
    local c4 = int_to_count(b4);

    # sabitleri count olarak kur ki aritmetik/bitwise sorunsuz olsun
    const K256: count = 256;
    const K65536: count = 65536;
    const K16777216: count = 16777216;

    local mask: count = c1 + K256*c2 + K65536*c3 + K16777216*c4;

    local out: set[string];
    for ( f in FLAGS )
        if ( (mask & f) != 0 )
            add out[FLAGS[f]];

    return out;
    }

# set[string] → "a,b,c"
function join(names: set[string], sep: string): string
    {
    local first = T;
    local out = "";
    for ( n in names )
        {
        if ( first ) { out = n; first = F; }
        else         { out = out + sep + n; }
        }
    return out;
    }
