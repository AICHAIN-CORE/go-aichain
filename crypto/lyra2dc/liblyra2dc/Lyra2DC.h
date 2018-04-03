#ifndef LYRA2DC_H
#define LYRA2DC_H

#ifdef __cplusplus
extern "C" {
#endif

// input : fixed to 80 bytes data length
void lyra2dc_hash(const unsigned char* input, size_t in_len, unsigned char* output);

#ifdef __cplusplus
}
#endif

#endif
