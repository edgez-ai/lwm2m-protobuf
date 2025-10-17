// Helper utilities implementation
//
// This file provides decoding helpers and related utility functions for the
// statically sized nanopb generated messages.

#include "lwm2m_helpers.h"
#include <pb_decode.h>
#include <string.h>

#ifdef ESP_PLATFORM
/* ESP-IDF includes for cryptographic functions */
#include "mbedtls/ecdh.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"
#include "esp_log.h"

static const char *TAG = "LWM2M_CRYPTO";

/* Constant-time memory comparison to prevent timing attacks */
static int constant_time_memcmp(const void *a, const void *b, size_t len) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result;
}
#else
/* For non-ESP platforms, you would need to link against mbedTLS or similar */
#warning "ECDH AES key derivation and ChaCha20-Poly1305 require mbedTLS for non-ESP platforms"
#endif

/* Return codes:
 *  0  success
 * -1  invalid arguments
 * -2  decode failure (malformed protobuf)
 * -3  size validation failure (unexpected field lengths)
 */
int lwm2m_read_factory_partition(const uint8_t *buffer, const size_t buffer_len, lwm2m_FactoryPartition *partition) {
	if (!buffer || !partition || buffer_len == 0) {
		return -1; /* invalid args */
	}

	/* Reset output struct to known zero state */
	*partition = (lwm2m_FactoryPartition)lwm2m_FactoryPartition_init_zero;

	pb_istream_t stream = pb_istream_from_buffer(buffer, buffer_len);
	if (!pb_decode(&stream, lwm2m_FactoryPartition_fields, partition)) {
		return -2; /* decode error */
	}

	return 0; /* success */
}

#ifdef ESP_PLATFORM
int lwm2m_ecdh_derive_aes_key(const uint8_t *public_key, const uint8_t *private_key,
                              uint8_t *derived_key, const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len) {
    if (!public_key || !private_key || !derived_key) {
        ESP_LOGE(TAG, "Invalid arguments: NULL pointers");
        return -1;
    }

    int ret = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point peer_public_point;
    mbedtls_mpi private_mpi;
    mbedtls_mpi shared_secret_mpi;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t shared_secret[32]; /* P-256 shared secret is 32 bytes */
    
    /* Initialize all contexts and structures */
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peer_public_point);
    mbedtls_mpi_init(&private_mpi);
    mbedtls_mpi_init(&shared_secret_mpi);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /* Seed the random number generator */
    const char *pers = "lwm2m_ecdh_derive";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to seed RNG: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Setup ECP group for secp256r1 (P-256) */
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load ECP group: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Load our private key */
    ret = mbedtls_mpi_read_binary(&private_mpi, private_key, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load private key: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Load peer's public key (assuming uncompressed format: 0x04 + 32 bytes X + 32 bytes Y) */
    if (public_key[0] != 0x04) {
        ESP_LOGE(TAG, "Unsupported public key format (expected uncompressed)");
        ret = -1;
        goto cleanup;
    }

    ret = mbedtls_ecp_point_read_binary(&grp, &peer_public_point, public_key, 65);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load public key: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Compute the shared secret using ECDH */
    ret = mbedtls_ecdh_compute_shared(&grp, &shared_secret_mpi, &peer_public_point, &private_mpi,
                                     mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "ECDH computation failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Export shared secret to binary format */
    ret = mbedtls_mpi_write_binary(&shared_secret_mpi, shared_secret, sizeof(shared_secret));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to export shared secret: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Use HKDF-SHA256 to derive the AES key from the shared secret */
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        ESP_LOGE(TAG, "Failed to get SHA256 MD info");
        ret = -3;
        goto cleanup;
    }

    ret = mbedtls_hkdf(md_info, salt, salt_len, shared_secret, sizeof(shared_secret),
                      info, info_len, derived_key, 32);
    if (ret != 0) {
        ESP_LOGE(TAG, "HKDF derivation failed: -0x%04x", -ret);
        ret = -3;
        goto cleanup;
    }

    ESP_LOGI(TAG, "ECDH AES key derivation successful");
    ret = 0;

cleanup:
    /* Clear sensitive data */
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
    
    /* Free all contexts and structures */
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&peer_public_point);
    mbedtls_mpi_free(&private_mpi);
    mbedtls_mpi_free(&shared_secret_mpi);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return ret;
}

#else /* !ESP_PLATFORM */

int lwm2m_ecdh_derive_aes_key(const uint8_t *public_key, const uint8_t *private_key,
                              uint8_t *derived_key, const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len) {
    /* Suppress unused parameter warnings */
    (void)public_key;
    (void)private_key;
    (void)derived_key;
    (void)salt;
    (void)salt_len;
    (void)info;
    (void)info_len;
    
    /* Not implemented for non-ESP platforms */
    return -2;
}

#endif /* ESP_PLATFORM */

int lwm2m_ecdh_derive_aes_key_simple(const uint8_t *public_key, const uint8_t *private_key,
                                     uint8_t *derived_key) {
    const char *info = "LwM2M-AES-Key";
    return lwm2m_ecdh_derive_aes_key(public_key, private_key, derived_key, 
                                    NULL, 0, /* no salt */
                                    (const uint8_t *)info, strlen(info));
}

#ifdef ESP_PLATFORM

/* Helper function to compute Poly1305 MAC */
static int compute_poly1305_tag(const uint8_t *key, const uint8_t *aad, size_t aad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t *tag) {
    mbedtls_poly1305_context poly1305_ctx;
    int ret;
    
    mbedtls_poly1305_init(&poly1305_ctx);
    
    ret = mbedtls_poly1305_starts(&poly1305_ctx, key);
    if (ret != 0) {
        goto cleanup;
    }
    
    /* Process AAD if present */
    if (aad && aad_len > 0) {
        ret = mbedtls_poly1305_update(&poly1305_ctx, aad, aad_len);
        if (ret != 0) {
            goto cleanup;
        }
        
        /* Pad AAD to 16-byte boundary */
        size_t aad_pad_len = (16 - (aad_len % 16)) % 16;
        if (aad_pad_len > 0) {
            uint8_t padding[16] = {0};
            ret = mbedtls_poly1305_update(&poly1305_ctx, padding, aad_pad_len);
            if (ret != 0) {
                goto cleanup;
            }
        }
    }
    
    /* Process ciphertext */
    if (ciphertext && ciphertext_len > 0) {
        ret = mbedtls_poly1305_update(&poly1305_ctx, ciphertext, ciphertext_len);
        if (ret != 0) {
            goto cleanup;
        }
        
        /* Pad ciphertext to 16-byte boundary */
        size_t cipher_pad_len = (16 - (ciphertext_len % 16)) % 16;
        if (cipher_pad_len > 0) {
            uint8_t padding[16] = {0};
            ret = mbedtls_poly1305_update(&poly1305_ctx, padding, cipher_pad_len);
            if (ret != 0) {
                goto cleanup;
            }
        }
    }
    
    /* Add lengths in little-endian format */
    uint8_t lengths[16];
    /* AAD length (64-bit little-endian) */
    for (int i = 0; i < 8; i++) {
        lengths[i] = (aad_len >> (i * 8)) & 0xFF;
    }
    /* Ciphertext length (64-bit little-endian) */
    for (int i = 0; i < 8; i++) {
        lengths[8 + i] = (ciphertext_len >> (i * 8)) & 0xFF;
    }
    
    ret = mbedtls_poly1305_update(&poly1305_ctx, lengths, sizeof(lengths));
    if (ret != 0) {
        goto cleanup;
    }
    
    ret = mbedtls_poly1305_finish(&poly1305_ctx, tag);

cleanup:
    mbedtls_poly1305_free(&poly1305_ctx);
    return ret;
}

int lwm2m_chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *plaintext, size_t plaintext_len,
                                    const uint8_t *aad, size_t aad_len,
                                    uint8_t *ciphertext, uint8_t *tag) {
    if (!key || !nonce || !tag || (plaintext_len > 0 && (!plaintext || !ciphertext))) {
        ESP_LOGE(TAG, "Invalid arguments for ChaCha20-Poly1305 encryption");
        return -1;
    }

    int ret = 0;
    mbedtls_chacha20_context chacha20_ctx;
    uint8_t poly1305_key[32] = {0};
    
    mbedtls_chacha20_init(&chacha20_ctx);

    /* Initialize ChaCha20 with key and nonce */
    ret = mbedtls_chacha20_setkey(&chacha20_ctx, key);
    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20 setkey failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    ret = mbedtls_chacha20_starts(&chacha20_ctx, nonce, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20 starts failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Generate Poly1305 key using first 32 bytes of ChaCha20 keystream */
    ret = mbedtls_chacha20_update(&chacha20_ctx, 32, poly1305_key, poly1305_key);
    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20 Poly1305 key generation failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Encrypt the plaintext if present */
    if (plaintext_len > 0) {
        ret = mbedtls_chacha20_update(&chacha20_ctx, plaintext_len, plaintext, ciphertext);
        if (ret != 0) {
            ESP_LOGE(TAG, "ChaCha20 encryption failed: -0x%04x", -ret);
            ret = -2;
            goto cleanup;
        }
    }

    /* Compute Poly1305 authentication tag */
    ret = compute_poly1305_tag(poly1305_key, aad, aad_len, ciphertext, plaintext_len, tag);
    if (ret != 0) {
        ESP_LOGE(TAG, "Poly1305 tag computation failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    ESP_LOGI(TAG, "ChaCha20-Poly1305 encryption successful");
    ret = 0;

cleanup:
    /* Clear sensitive data */
    mbedtls_platform_zeroize(poly1305_key, sizeof(poly1305_key));
    mbedtls_chacha20_free(&chacha20_ctx);
    return ret;
}

int lwm2m_chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *ciphertext, size_t ciphertext_len,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *tag, uint8_t *plaintext) {
    if (!key || !nonce || !tag || (ciphertext_len > 0 && (!ciphertext || !plaintext))) {
        ESP_LOGE(TAG, "Invalid arguments for ChaCha20-Poly1305 decryption");
        return -1;
    }

    int ret = 0;
    mbedtls_chacha20_context chacha20_ctx;
    uint8_t poly1305_key[32] = {0};
    uint8_t computed_tag[16];
    
    mbedtls_chacha20_init(&chacha20_ctx);

    /* Initialize ChaCha20 with key and nonce */
    ret = mbedtls_chacha20_setkey(&chacha20_ctx, key);
    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20 setkey failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    ret = mbedtls_chacha20_starts(&chacha20_ctx, nonce, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20 starts failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Generate Poly1305 key using first 32 bytes of ChaCha20 keystream */
    ret = mbedtls_chacha20_update(&chacha20_ctx, 32, poly1305_key, poly1305_key);
    if (ret != 0) {
        ESP_LOGE(TAG, "ChaCha20 Poly1305 key generation failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Verify authentication tag before decryption */
    ret = compute_poly1305_tag(poly1305_key, aad, aad_len, ciphertext, ciphertext_len, computed_tag);
    if (ret != 0) {
        ESP_LOGE(TAG, "Poly1305 tag computation failed: -0x%04x", -ret);
        ret = -2;
        goto cleanup;
    }

    /* Constant-time tag comparison */
    if (constant_time_memcmp(tag, computed_tag, 16) != 0) {
        ESP_LOGE(TAG, "Authentication tag verification failed");
        ret = -3;
        goto cleanup;
    }

    /* Decrypt the ciphertext if present */
    if (ciphertext_len > 0) {
        ret = mbedtls_chacha20_update(&chacha20_ctx, ciphertext_len, ciphertext, plaintext);
        if (ret != 0) {
            ESP_LOGE(TAG, "ChaCha20 decryption failed: -0x%04x", -ret);
            ret = -2;
            goto cleanup;
        }
    }

    ESP_LOGI(TAG, "ChaCha20-Poly1305 decryption successful");
    ret = 0;

cleanup:
    /* Clear sensitive data */
    mbedtls_platform_zeroize(poly1305_key, sizeof(poly1305_key));
    mbedtls_platform_zeroize(computed_tag, sizeof(computed_tag));
    mbedtls_chacha20_free(&chacha20_ctx);
    return ret;
}

int lwm2m_chacha20_generate_nonce(uint8_t *nonce) {
    if (!nonce) {
        ESP_LOGE(TAG, "Invalid arguments for nonce generation");
        return -1;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret = 0;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "lwm2m_chacha20_nonce";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to seed RNG for nonce generation: -0x%04x", -ret);
        ret = -1;
        goto cleanup;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, nonce, 12);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to generate random nonce: -0x%04x", -ret);
        ret = -1;
        goto cleanup;
    }

    ESP_LOGI(TAG, "ChaCha20 nonce generation successful");
    ret = 0;

cleanup:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    return ret;
}

#else /* !ESP_PLATFORM */

int lwm2m_chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *plaintext, size_t plaintext_len,
                                    const uint8_t *aad, size_t aad_len,
                                    uint8_t *ciphertext, uint8_t *tag) {
    /* Suppress unused parameter warnings */
    (void)key; (void)nonce; (void)plaintext; (void)plaintext_len;
    (void)aad; (void)aad_len; (void)ciphertext; (void)tag;
    
    /* Not implemented for non-ESP platforms */
    return -2;
}

int lwm2m_chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *ciphertext, size_t ciphertext_len,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *tag, uint8_t *plaintext) {
    /* Suppress unused parameter warnings */
    (void)key; (void)nonce; (void)ciphertext; (void)ciphertext_len;
    (void)aad; (void)aad_len; (void)tag; (void)plaintext;
    
    /* Not implemented for non-ESP platforms */
    return -2;
}

int lwm2m_chacha20_generate_nonce(uint8_t *nonce) {
    /* Suppress unused parameter warnings */
    (void)nonce;
    
    /* Not implemented for non-ESP platforms */
    return -1;
}

#endif /* ESP_PLATFORM */

