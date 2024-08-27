module main;

import cascrypt;
import std.stdio;
import std.conv;
import std.exception : assertThrown;
import std.utf;

void main() {
    string message = "Wohowergwvergqcwefqwefqwefqcec! weroo";
    ubyte[16] key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    
    
    ubyte[] data = cast(ubyte[])message.idup;
    ubyte[] encrypted = cascryptEncrypt(data, key);
    ubyte[] decrypted = cascryptDecrypt(encrypted, key);

    writeln("Original Message: ", message);
    writeln("Encrypted Data: ", encrypted);
    writeln("Decrypted Message: ", cast(string)decrypted);
}
