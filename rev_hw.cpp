#include <string>
#include <cstdint>
#include <cstring>

#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "rev_hw.hpp"
#include "rev_hw_wapcbctable.hpp"

/* Start $1 */
const uint8_t g_aucEncryptionKey_AES256[] = {
    0xb8, 0x36, 0x3c, 0x9b, 0x77, 0xda, 0xed, 0x4b, 0x9a, 0xbb, 0x9f,
    0x2f, 0x6d, 0xf5, 0xf1, 0xd5, 0xcb, 0x64, 0x97, 0x5d, 0x5d, 0x3b,
    0xce, 0xe8, 0x82, 0x7f, 0x2f, 0x42, 0x23, 0x5f, 0x92, 0x29
}; //"b8363c9b77daed4b9abb9f2f6df5f1d5cb64975d5d3bcee8827f2f42235f9229";

const uint32_t g_auiRandomSaltPos_AES256[] = { 0xB, 0x11, 0x17, 0x1D };
/* End $1 */

/* Start $2 */
const uint8_t g_aucBasicEncryptionKey_AESCBC256[] = {
    0x3b, 0x5e, 0xa3, 0xbb, 0x4e, 0xdf, 0xcb, 0xd5, 0xc7, 0xc3, 0x1f,
    0x0d, 0x7d, 0x5c, 0x67, 0x96, 0x2a, 0x72, 0x9d, 0xd2, 0x1d, 0x05,
    0x5d, 0x1a, 0xeb, 0x1c, 0xa3, 0x17, 0x4a, 0x73, 0xab, 0xce
}; //"3b5ea3bb4edfcbd5c7c31f0d7d5c67962a729dd21d055d1aeb1ca3174a73abce";

// Key from library's.so
const uint8_t g_strKey[] = "Df7!ui%s9(lmV1L8";
/* End $2 */

void
debug_printbuf(const char *prolog, const char *fmt, void *buf, int sz)
{
    std::printf("%s: ", prolog);
    for (int i = 0; i < sz; ++i) {
        std::printf(fmt, reinterpret_cast<uint8_t *>(buf)[i]);
    }
    std::printf("\n");
}

void
rev_HW_AES_AscVisible(uint8_t *p_str, uint32_t p_sz)
{
    for (uint32_t i = 0; i < p_sz; ++i) {
        p_str[i] = (p_str[i] == 0x1E ? '~' : p_str[i] + 0x21);
    }
}

void
rev_HW_AES_AscUnvisible(uint8_t *p_bin, uint32_t p_sz)
{
    for (uint32_t i = 0; i < p_sz; ++i) {
        p_bin[i] = (p_bin[i] == '~' ? 0x1E : p_bin[i] - 0x21);
    }
}

void
rev_HW_AES_LongToAesEnhSys(uint32_t in_long, uint8_t *out_plain)
{
    constexpr uint32_t delim = 93;

    do {
        *out_plain++ = in_long % delim;
        in_long /= delim;
    } while (in_long);
}

void
rev_HW_AES_AesEnhSysToLong(const uint8_t *in_plain, uint32_t *out_long)
{
    *out_long = 0;
    for (uint32_t i = 0, vMul = 1; i < 5; ++i, vMul *= 93) {
        *out_long += vMul * in_plain[i];
    }
}

void
rev_HW_AES_BinToPlain(const uint8_t *in_bin, uint8_t *out_plain)
{
    for (uint32_t i = 0, long_bin; i < 4; ++i, out_plain += 5) {
        long_bin = reinterpret_cast<const uint32_t *>(in_bin)[i];
        rev_HW_AES_LongToAesEnhSys(long_bin, out_plain);
    }
};

void
rev_HW_AES_PlainToBin(const uint8_t *in_plain, uint8_t *out_bin)
{
    for (uint32_t i = 0, long_bin; i < 4; ++i, in_plain += 5) {
        rev_HW_AES_AesEnhSysToLong(in_plain, &long_bin);
        reinterpret_cast<uint32_t *>(out_bin)[i] = long_bin;
    }
};

void
rev_HW_AES_AesEncrypt(const char *p_str, uint32_t p_sz, std::string &enc_pass)
{
    AES_KEY aes_key;
    uint8_t user_aes_key[SHA256_DIGEST_LENGTH] = { 0 };
    uint8_t pwd_salt[4];

    static_assert(sizeof(g_aucEncryptionKey_AES256) <= sizeof(user_aes_key),
                  "check size");
    std::memcpy(
        user_aes_key, g_aucEncryptionKey_AES256, sizeof(g_aucEncryptionKey_AES256));

    RAND_bytes(pwd_salt, sizeof(pwd_salt));

    for (size_t i = 0; i < sizeof(pwd_salt); ++i) {
        pwd_salt[i] %= 93;
        user_aes_key[g_auiRandomSaltPos_AES256[i]] = pwd_salt[i];
    }

    AES_set_encrypt_key(user_aes_key, 256, &aes_key);

    for (size_t i = 0, cp_block_sz = AES_BLOCK_SIZE; i < p_sz; i += cp_block_sz) {

        uint8_t bin_enc_block[24] = { 0 };

        uint8_t aes_enc_block[AES_BLOCK_SIZE] = { 0 };
        uint8_t str_dec_block[AES_BLOCK_SIZE] = { 0 };

        if (i + cp_block_sz >= p_sz) {
            cp_block_sz = p_sz - i;
        }

        std::memcpy(str_dec_block, p_str + i, cp_block_sz);
        std::memcpy(bin_enc_block + 20, pwd_salt, sizeof(pwd_salt));

        AES_encrypt(str_dec_block, aes_enc_block, &aes_key);

        rev_HW_AES_BinToPlain(aes_enc_block, bin_enc_block);

        enc_pass.append(bin_enc_block, bin_enc_block + sizeof(bin_enc_block));
    }
}

void
rev_HW_AES_AesDecrypt(const char *p_bin, uint32_t p_sz, std::string &dec_pass)
{
    AES_KEY aes_key;
    uint8_t user_aes_key[SHA256_DIGEST_LENGTH] = { 0 };

    auto passwd_bin = reinterpret_cast<const uint8_t *>(p_bin);

    uint32_t enc_block_count = p_sz / 24;

    if (p_sz != 24 * (p_sz / 24)) {
        enc_block_count++;
    }

    if (p_sz < enc_block_count * 24) {
        return;
    }

    static_assert(sizeof(g_aucEncryptionKey_AES256) <= sizeof(user_aes_key),
                  "check size");
    std::memcpy(
        user_aes_key, g_aucEncryptionKey_AES256, sizeof(g_aucEncryptionKey_AES256));

    for (uint32_t i = 0; i < 4; i++) {
        user_aes_key[g_auiRandomSaltPos_AES256[i]] = passwd_bin[20 + i];
    }

    AES_set_decrypt_key(user_aes_key, 256, &aes_key);

    for (uint32_t i = 0, j = 0; i < enc_block_count; ++i, j += 24) {

        uint8_t aes_enc_block[AES_BLOCK_SIZE]            = { 0 };
        uint8_t str_dec_block[sizeof(aes_enc_block) + 1] = { 0 };

        rev_HW_AES_PlainToBin(passwd_bin + j, aes_enc_block);

        AES_decrypt(aes_enc_block, str_dec_block, &aes_key);

        //    std::printf("\n\tDecrypt block [%d] = '%s'", i, str_dec_block);
        dec_pass.append(reinterpret_cast<char *>(str_dec_block));
    }
}

void
rev_HW_AES_AesCBCEncrypt(const char *p_str, uint32_t p_sz, std::string &enc_pass)
{
    AES_KEY aes_key;
    uint8_t IV_AES[AES_BLOCK_SIZE]             = { 0 };
    uint8_t dec_cbc_key[SHA256_DIGEST_LENGTH]  = { 0 };
    uint8_t user_aes_key[SHA256_DIGEST_LENGTH] = { 0 };

    uint8_t iv_enc_block[20] = { 0 };

    rev_HW_AES_WboxDecrypt(&g_aucBasicEncryptionKey_AESCBC256[0], &dec_cbc_key[0]);
    rev_HW_AES_WboxDecrypt(&g_aucBasicEncryptionKey_AESCBC256[16], &dec_cbc_key[16]);

    SHA256_CTX sctx;
    SHA256_Init(&sctx);
    SHA256_Update(&sctx, dec_cbc_key, sizeof(dec_cbc_key));
    SHA256_Update(&sctx, g_strKey, sizeof(g_strKey) - 1);
    SHA256_Final(user_aes_key, &sctx);

    RAND_bytes(IV_AES, sizeof(IV_AES));
    rev_HW_AES_BinToPlain(IV_AES, iv_enc_block);

    AES_set_encrypt_key(user_aes_key, 256, &aes_key);

    for (size_t i = 0, cp_block_sz = AES_BLOCK_SIZE; i < p_sz; i += cp_block_sz) {

        uint8_t bin_enc_block[20] = { 0 };

        uint8_t aes_enc_block[AES_BLOCK_SIZE] = { 0 };
        uint8_t str_dec_block[AES_BLOCK_SIZE] = { 0 };

        if (i + cp_block_sz >= p_sz) {
            cp_block_sz = p_sz - i;
        }

        std::memcpy(str_dec_block, p_str + i, cp_block_sz);

        AES_cbc_encrypt(str_dec_block, aes_enc_block, 16, &aes_key, IV_AES, AES_ENCRYPT);

        rev_HW_AES_BinToPlain(aes_enc_block, bin_enc_block);

        enc_pass.append(bin_enc_block, bin_enc_block + sizeof(bin_enc_block));
    }
    enc_pass.append(iv_enc_block, iv_enc_block + sizeof(iv_enc_block));
}

void
rev_HW_AES_AesCBCDecrypt(const char *p_bin, uint32_t p_sz, std::string &dec_pass)
{
    AES_KEY aes_key;
    uint8_t IV_AES[AES_BLOCK_SIZE]             = { 0 };
    uint8_t dec_cbc_key[SHA256_DIGEST_LENGTH]  = { 0 };
    uint8_t user_aes_key[SHA256_DIGEST_LENGTH] = { 0 };

    auto passwd_bin = reinterpret_cast<const uint8_t *>(p_bin);

    uint32_t enc_block_count = p_sz / 20;

    if (p_sz != 20 * (p_sz / 20)) {
        enc_block_count++;
    }

    if (p_sz < enc_block_count * 20) {
        return;
    }

    rev_HW_AES_WboxDecrypt(&g_aucBasicEncryptionKey_AESCBC256[0], &dec_cbc_key[0]);
    rev_HW_AES_WboxDecrypt(&g_aucBasicEncryptionKey_AESCBC256[16], &dec_cbc_key[16]);

    SHA256_CTX sctx;
    SHA256_Init(&sctx);
    SHA256_Update(&sctx, dec_cbc_key, sizeof(dec_cbc_key));
    SHA256_Update(&sctx, g_strKey, sizeof(g_strKey) - 1);
    SHA256_Final(user_aes_key, &sctx);

    rev_HW_AES_PlainToBin(passwd_bin + 20 * enc_block_count - 20, IV_AES);

    AES_set_decrypt_key(user_aes_key, 256, &aes_key);

    for (uint32_t i = 0, j = 0; i < enc_block_count - 1; ++i, j += 20) {

        uint8_t aes_enc_block[AES_BLOCK_SIZE]            = { 0 };
        uint8_t str_dec_block[sizeof(aes_enc_block) + 1] = { 0 };

        rev_HW_AES_PlainToBin(passwd_bin + j, aes_enc_block);

        AES_cbc_encrypt(aes_enc_block, str_dec_block, 16, &aes_key, IV_AES, AES_DECRYPT);

        //    std::printf("\n\tDecrypt block [%d] = '%s'", i, str_dec_block);
        dec_pass.append(reinterpret_cast<char *>(str_dec_block));
    }
}

uint32_t
rev_HW_AES_ROTL(const uint32_t x, uint32_t bits, uint32_t block)
{
    const uint32_t n = bits % block;
    return ((x << n) | (x >> (block - n)));
}

void
rev_HW_AES_WboxDecrypt(const uint8_t *in_key, uint8_t *out_buf)
{
    // i_var_unkn_ = iterator variable unknow

    uint32_t arr_table[4] = { 0 };

    uint32_t arr_table_tmp[sizeof(arr_table) / sizeof(arr_table[0])] = { 0 };

    uint8_t un_XOR_buf[sizeof(arr_table /* uint32_t * 4 == 16 */)] = { 0 };

    for (uint16_t i_var_unkn_1 = 0,
                  i_var_unkn_2 = 0,
                  i_var_unkn_3 = 0,
                  i_var_unkn_4 = 0,
                  i            = 0;
         i_var_unkn_1 != 3120;
         i_var_unkn_1 += 195,
                  i_var_unkn_2 += 103,
                  i_var_unkn_3 += 9,
                  i_var_unkn_4 += 39,
                  i++) {

        uint8_t raw_ch = *in_key++;

        un_XOR_buf[i] = i_var_unkn_4;
        un_XOR_buf[i] ^= rev_HW_AES_ROTL(raw_ch, i_var_unkn_1, 8);
        un_XOR_buf[i] ^= rev_HW_AES_ROTL(raw_ch, i_var_unkn_2, 8);
        un_XOR_buf[i] ^= rev_HW_AES_ROTL(raw_ch, i_var_unkn_3, 8);
    }

    arr_table[0] = (un_XOR_buf[4]) | (un_XOR_buf[7] << 24) |
                   ((un_XOR_buf[5] << 8) & 0xFFFF) | ((un_XOR_buf[6]) << 16);
    arr_table[1] = (un_XOR_buf[8]) | (un_XOR_buf[11] << 24) |
                   ((un_XOR_buf[9] << 8) & 0xFFFF) | ((un_XOR_buf[10]) << 16);
    arr_table[2] = (un_XOR_buf[12]) | (un_XOR_buf[15] << 24) |
                   ((un_XOR_buf[13] << 8) & 0xFFFF) | ((un_XOR_buf[14]) << 16);
    arr_table[3] = (un_XOR_buf[0]) | (un_XOR_buf[3] << 24) |
                   ((un_XOR_buf[1] << 8) & 0xFFFF) | ((un_XOR_buf[2]) << 16);

    arr_table_tmp[0] =
        wapcbctable2[(arr_table[0] >> 24) | 0x300] ^ wapcbctable2[(un_XOR_buf[0])] ^
        wapcbctable2[(((un_XOR_buf[12]) | (un_XOR_buf[13] << 8)) >> 8) | 0x100] ^
        wapcbctable2[(un_XOR_buf[10]) | 0x200];

    arr_table_tmp[1] =
        wapcbctable2[(arr_table[1] >> 24) | 0x700] ^
        wapcbctable2[(un_XOR_buf[4]) | 0x400] ^
        wapcbctable2[(((un_XOR_buf[0]) | (un_XOR_buf[1] << 8)) >> 8) | 0x500] ^
        wapcbctable2[((arr_table[2] >> 16) & 0xFF) | 0x600];

    arr_table_tmp[2] =
        wapcbctable2[(arr_table[2] >> 24) | 0xB00] ^
        wapcbctable2[(un_XOR_buf[8]) | 0x800] ^
        wapcbctable2[(((un_XOR_buf[4]) | (un_XOR_buf[5] << 8)) >> 8) | 0x900] ^
        wapcbctable2[((arr_table[3] >> 16) & 0xFF) | 0xA00];

    arr_table_tmp[3] =
        wapcbctable2[(arr_table[3] >> 24) | 0xF00] ^
        wapcbctable2[(un_XOR_buf[12]) | 0xC00] ^
        wapcbctable2[(((un_XOR_buf[8]) | (un_XOR_buf[9] << 8)) >> 8) | 0xD00] ^
        wapcbctable2[((arr_table[0] >> 16) & 0xFF) | 0xE00];

    std::memcpy(arr_table, arr_table_tmp, sizeof(arr_table));

    for (int i = 0x1000; i <= 0xd000; i += 0x1000) {

        uint16_t mul0 = (i + 0x300);
        uint16_t mul1 = (i + 0x000);
        uint16_t mul2 = (i + 0x100);
        uint16_t mul3 = (i + 0x200);

        arr_table_tmp[0] =
            wapcbctable2[(arr_table[1] >> 24) | (mul0 + (0x400 * 0))] ^
            wapcbctable2[(uint8_t)(arr_table[0]) | (mul1 + (0x400 * 0))] ^
            wapcbctable2[((uint16_t)(arr_table[3]) >> 8) | (mul2 + (0x400 * 0))] ^
            wapcbctable2[((arr_table[2] >> 16) & 0xFF) | (mul3 + (0x400 * 0))];

        arr_table_tmp[1] =
            wapcbctable2[(arr_table[2] >> 24) | (mul0 + (0x400 * 1))] ^
            wapcbctable2[(uint8_t)(arr_table[1]) | (mul1 + (0x400 * 1))] ^
            wapcbctable2[((uint16_t)(arr_table[0]) >> 8) | (mul2 + (0x400 * 1))] ^
            wapcbctable2[((arr_table[3] >> 16) & 0xFF) | (mul3 + (0x400 * 1))];

        arr_table_tmp[2] =
            wapcbctable2[(arr_table[3] >> 24) | (mul0 + (0x400 * 2))] ^
            wapcbctable2[(uint8_t)(arr_table[2]) | (mul1 + (0x400 * 2))] ^
            wapcbctable2[((uint16_t)(arr_table[1]) >> 8) | (mul2 + (0x400 * 2))] ^
            wapcbctable2[((arr_table[0] >> 16) & 0xFF) | (mul3 + (0x400 * 2))];

        arr_table_tmp[3] =
            wapcbctable2[(arr_table[0] >> 24) | (mul0 + (0x400 * 3))] ^
            wapcbctable2[(uint8_t)(arr_table[3]) | (mul1 + (0x400 * 3))] ^
            wapcbctable2[((uint16_t)(arr_table[2]) >> 8) | (mul2 + (0x400 * 3))] ^
            wapcbctable2[((arr_table[1] >> 16) & 0xFF) | (mul3 + (0x400 * 3))];

        std::memcpy(arr_table, arr_table_tmp, sizeof(arr_table));
    }

    std::memcpy(un_XOR_buf, arr_table, sizeof(un_XOR_buf));

    for (uint16_t i = 0, i_var_unkn_5 = 0, i_var_unkn_6 = 0, i_var_unkn_7 = 0; i < 16;
         ++i, i_var_unkn_5 += 58, i_var_unkn_6 += 193, i_var_unkn_7 += 87) {

        uint8_t raw_ch = un_XOR_buf[i];

        out_buf[i] = i_var_unkn_7;
        out_buf[i] ^= rev_HW_AES_ROTL(raw_ch, i_var_unkn_5, 8);
        out_buf[i] ^= rev_HW_AES_ROTL(raw_ch, i_var_unkn_6, 8);
        out_buf[i] ^= rev_HW_AES_ROTL(raw_ch, 230 * i, 8);
    }
}
