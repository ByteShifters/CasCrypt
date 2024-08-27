module cascrypt;

import std.stdio;
import std.array;
import std.bitmanip;
import std.conv;
import std.range;

enum KEY_SIZE = 16;
enum BLOCK_SIZE = 500;
enum NUM_ROUNDS = 25;

ubyte[256] S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
    0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
    0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
    0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
    0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
    0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
    0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
    0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
    0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
    0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x6F, 0x3F, 0xEA, 0x8B, 0x7D, 0x4A, 0x5B, 0x8E, 0x40, 0x24, 0x30, 0x61, 0x13,
    0xC7, 0x6C, 0x2D, 0x8F, 0x0E, 0x6D, 0x3E, 0x0C, 0x9E, 0x6E, 0x27, 0x80, 0x51
];

ubyte[256] INV_S_BOX = [
    0x82, 0x09, 0x6A, 0x6F, 0x4F, 0xF5, 0x5C, 0x68, 0xB6, 0x7F, 0x52, 0x6B, 0x3D, 0x7A, 0xF7,
    0xB9, 0xE0, 0xB2, 0x8A, 0xD0, 0x16, 0xAD, 0x6D, 0x35, 0x7B, 0x4A, 0x9E, 0x6C, 0x1F, 0x9D,
    0x87, 0x85, 0x1E, 0x1B, 0x59, 0x8D, 0x92, 0x0F, 0xB0, 0xCE, 0xBB, 0x5B, 0xA6, 0x6E, 0x4E,
    0x8B, 0x47, 0xC5, 0x9C, 0xD2, 0xB7, 0x28, 0xC7, 0x5E, 0x38, 0xF0, 0xB8, 0xF4, 0xB1, 0x9F,
    0x63, 0x76, 0x1C, 0xD4, 0x47, 0x54, 0xD9, 0xF9, 0x0D, 0x18, 0x44, 0x23, 0x3F, 0x72, 0x80,
    0x5D, 0xAD, 0xB5, 0x22, 0x1D, 0x84, 0xA8, 0x6A, 0xA1, 0xE3, 0xB4, 0x68, 0x37, 0xD1, 0x40,
    0xE4, 0x8F, 0x7D, 0x5F, 0x29, 0x3C, 0xE6, 0x0E, 0x71, 0x71, 0xF3, 0x57, 0x62, 0xD3, 0x42,
    0x9F, 0x91, 0x95, 0x2E, 0x8E, 0x43, 0xF6, 0x9D, 0xE5, 0x8C, 0x50, 0x3B, 0xA5, 0xBD, 0x77,
    0xAE, 0x9F, 0xB3, 0x78, 0xA7, 0xA9, 0xF1, 0xD6, 0xE8, 0x21, 0xCF, 0xE9, 0x6C, 0xF2, 0xD2,
    0x63, 0xB8, 0x84, 0xB2, 0x0A, 0xBD, 0x4C, 0x56, 0xEC, 0x5D, 0x7A, 0xAA, 0xD8, 0x9C, 0x62,
    0x7E, 0x0B, 0xBF, 0xE9, 0x53, 0xB8, 0x6C, 0x8C, 0x8F, 0xF7, 0x55, 0xD6, 0x68, 0xF0, 0x1D,
    0xF8, 0xF4, 0xD9, 0x2B, 0x1A, 0x5F, 0xA5, 0xF8, 0xD6, 0xC9, 0xB3, 0xC2, 0xA8, 0x4E, 0x47
];

void permute(ref ubyte[BLOCK_SIZE] state) {
    ubyte[BLOCK_SIZE] temp;
    temp[0] = state[0];
    temp[1] = state[5];
    temp[2] = state[10];
    temp[3] = state[15];
    temp[4] = state[4];
    temp[5] = state[9];
    temp[6] = state[14];
    temp[7] = state[3];
    temp[8] = state[8];
    temp[9] = state[13];
    temp[10] = state[2];
    temp[11] = state[7];
    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];
    state[] = temp[];
}

void inversePermute(ref ubyte[BLOCK_SIZE] state) {
    ubyte[BLOCK_SIZE] temp;
    temp[0] = state[0];
    temp[1] = state[13];
    temp[2] = state[10];
    temp[3] = state[7];
    temp[4] = state[12];
    temp[5] = state[1];
    temp[6] = state[14];
    temp[7] = state[11];
    temp[8] = state[4];
    temp[9] = state[5];
    temp[10] = state[2];
    temp[11] = state[15];
    temp[12] = state[8];
    temp[13] = state[9];
    temp[14] = state[6];
    temp[15] = state[3];
    state[] = temp[];
}

void mixLayer(ref ubyte[BLOCK_SIZE] state) {
    ubyte[BLOCK_SIZE] temp;
    foreach (i; 0..BLOCK_SIZE) {
        temp[i] = cast(ubyte)((state[i] * 2) ^ (state[(i + 1) % BLOCK_SIZE] * 3) ^ state[(i + 2) % BLOCK_SIZE]);
    }
    state[] = temp[];
}

void inverseMixLayer(ref ubyte[BLOCK_SIZE] state) {
    ubyte[BLOCK_SIZE] temp;
    foreach (i; 0..BLOCK_SIZE) {
        temp[i] = cast(ubyte)((state[i] * 3) ^ (state[(i + 1) % BLOCK_SIZE] * 2) ^ state[(i + 2) % BLOCK_SIZE]);
    }
    state[] = temp[];
}

ubyte[KEY_SIZE][NUM_ROUNDS + 1] keySchedule(ubyte[KEY_SIZE] key) {
    ubyte[KEY_SIZE][NUM_ROUNDS + 1] roundKeys;
    roundKeys[0] = key;

    foreach (i; 1..NUM_ROUNDS + 1) {
        roundKeys[i] = roundKeys[i - 1].dup;
        foreach (j; 0..KEY_SIZE) {
            int temp = S_BOX[roundKeys[i - 1][(j + 1) % KEY_SIZE]] ^ (i * j);
            roundKeys[i][j] = cast(ubyte)temp;
        }
    }

    return roundKeys;
}

void encryptBlock(ref ubyte[BLOCK_SIZE] block, ubyte[KEY_SIZE][NUM_ROUNDS + 1] roundKeys) {
    writeln("Original Block: ", block);

    foreach (i; 0..BLOCK_SIZE) {
        block[i] ^= roundKeys[0][i];
    }
    writeln("After Initial Key Addition: ", block);

    foreach (round; 1..NUM_ROUNDS) {
        foreach (i; 0..BLOCK_SIZE) {
            block[i] = S_BOX[block[i]];
        }
        writeln("After Substitution Round ", round, ": ", block);

        permute(block);
        writeln("After Permutation Round ", round, ": ", block);

        mixLayer(block);
        writeln("After Mixing Round ", round, ": ", block);

        foreach (i; 0..BLOCK_SIZE) {
            block[i] ^= roundKeys[round][i];
        }
        writeln("After Round Key Addition Round ", round, ": ", block);
    }

    foreach (i; 0..BLOCK_SIZE) {
        block[i] = S_BOX[block[i]];
    }
    writeln("After Final Substitution: ", block);

    foreach (i; 0..BLOCK_SIZE) {
        block[i] ^= roundKeys[NUM_ROUNDS][i];
    }
    writeln("After Final Key Addition: ", block);
}

void decryptBlock(ref ubyte[BLOCK_SIZE] block, ubyte[KEY_SIZE][NUM_ROUNDS + 1] roundKeys) {
    writeln("Encrypted Block: ", block);

    foreach (i; 0..BLOCK_SIZE) {
        block[i] ^= roundKeys[NUM_ROUNDS][i];
    }
    writeln("After Final Key Addition: ", block);

    foreach (i; 0..BLOCK_SIZE) {
        block[i] = INV_S_BOX[block[i]];
    }
    writeln("After Final Substitution: ", block);

    foreach_reverse (round; 1..NUM_ROUNDS) {
        foreach (i; 0..BLOCK_SIZE) {
            block[i] ^= roundKeys[round][i];
        }
        writeln("After Round Key Addition Round ", round, ": ", block);

        inverseMixLayer(block);
        writeln("After Inverse Mixing Round ", round, ": ", block);

        inversePermute(block);
        writeln("After Inverse Permutation Round ", round, ": ", block);

        foreach (i; 0..BLOCK_SIZE) {
            block[i] = INV_S_BOX[block[i]];
        }
        writeln("After Inverse Substitution Round ", round, ": ", block);
    }

    foreach (i; 0..BLOCK_SIZE) {
        block[i] ^= roundKeys[0][i];
    }
    writeln("After Initial Key Addition: ", block);
}

ubyte[] cascryptEncrypt(const ubyte[] data, const ubyte[] key) {
    assert(key.length == KEY_SIZE, "Invalid key size");
    ubyte[KEY_SIZE][NUM_ROUNDS + 1] roundKeys = keySchedule(key.staticArray!(ubyte[KEY_SIZE]));

    ubyte[] encrypted = data.dup;
    foreach (i; 0 .. encrypted.length / BLOCK_SIZE) {
        auto block = encrypted[i * BLOCK_SIZE .. (i + 1) * BLOCK_SIZE];
        encryptBlock(*cast(ubyte[BLOCK_SIZE]*)block.ptr, roundKeys);
    }

    return encrypted;
}

ubyte[] cascryptDecrypt(const ubyte[] data, const ubyte[] key) {
    assert(key.length == KEY_SIZE, "Invalid key size");
    ubyte[KEY_SIZE][NUM_ROUNDS + 1] roundKeys = keySchedule(key.staticArray!(ubyte[KEY_SIZE]));

    ubyte[] decrypted = data.dup;
    foreach (i; 0 .. decrypted.length / BLOCK_SIZE) {
        auto block = decrypted[i * BLOCK_SIZE .. (i + 1) * BLOCK_SIZE];
        decryptBlock(*cast(ubyte[BLOCK_SIZE]*)block.ptr, roundKeys);
    }

    return decrypted;
}
