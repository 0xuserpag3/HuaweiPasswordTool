#ifndef REV_HW_H
#define REV_HW_H

#include <string>
#include <cstdint>

extern const uint8_t g_aucEncryptionKey_AES256[];
extern const uint32_t g_auiRandomSaltPos_AES256[];

extern const uint8_t g_aucBasicEncryptionKey_AESCBC256[];
extern const uint8_t g_strKey[];

void rev_HW_AES_AscVisible(uint8_t *p_str, uint32_t p_sz);
void rev_HW_AES_AscUnvisible(uint8_t *p_bin, uint32_t p_sz);

void rev_HW_AES_BinToPlain(const uint8_t *in_bin, uint8_t *out_plain);
void rev_HW_AES_PlainToBin(const uint8_t *in_plain, uint8_t *out_bin);

void rev_HW_AES_LongToAesEnhSys(uint32_t in_long, uint8_t *out_plain);
void rev_HW_AES_AesEnhSysToLong(const uint8_t *in_plain, uint32_t *out_long);

void rev_HW_AES_AesEncrypt(const char *p_str, uint32_t p_sz, std::string &enc_pass);
void rev_HW_AES_AesDecrypt(const char *p_bin, uint32_t p_sz, std::string &dec_pass);

void rev_HW_AES_AesCBCEncrypt(const char *p_str, uint32_t p_sz, std::string &enc_pass);
void rev_HW_AES_AesCBCDecrypt(const char *p_bin, uint32_t p_sz, std::string &dec_pass);

void rev_HW_AES_WboxDecrypt(const uint8_t *in_key, uint8_t *out_buf);

uint32_t rev_HW_AES_ROTL(const uint32_t x, uint32_t bits, uint32_t block);

#endif // REV_HW_H
