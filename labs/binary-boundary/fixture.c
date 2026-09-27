/* Original inert analysis fixture. No imports, entry point, I/O, or pointer dereferences. */
typedef unsigned char u8;
typedef unsigned int u32;
typedef char u32_must_be_four_bytes[(sizeof(u32) == 4) ? 1 : -1];

__declspec(dllexport) int legacy_boolean(u8 value) {
    return value != 0;
}

__declspec(dllexport) int canonical_boolean(u8 value) {
    return value <= 1 ? (int)value : -1;
}

__declspec(dllexport) int legacy_range(u32 total, u32 offset, u32 count) {
    return offset + count <= total;
}

__declspec(dllexport) int bounded_range(u32 total, u32 offset, u32 count) {
    return offset <= total && count <= total - offset;
}
