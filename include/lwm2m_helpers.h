#ifndef LWM2M_HELPERS_H_
#define LWM2M_HELPERS_H_

#include <stddef.h>
#include <stdint.h>
#include "lwm2m.pb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* LwM2M Protocol Buffer Helper Functions
 * 
 * This library provides utilities for working with LwM2M protobuf messages,
 * including cryptographic operations for secure device communications.
 * 
 * Example usage for ECDH AES key derivation:
 *
 *   uint8_t peer_public_key[65];  // 0x04 + 32-byte X + 32-byte Y (uncompressed P-256)
 *   uint8_t our_private_key[32];  // 32-byte private key for P-256
 *   uint8_t derived_aes_key[32];  // Output: 256-bit AES key
 *
 *   // Simple derivation (recommended for most use cases)
 *   int result = lwm2m_ecdh_derive_aes_key_simple(peer_public_key, our_private_key, derived_aes_key);
 *   if (result == 0) {
 *       // Use derived_aes_key for AES-256-GCM encryption/decryption
 *   }
 *
 *   // Advanced derivation with custom salt and info
 *   const char *salt = "my-salt";
 *   const char *info = "my-context-info";
 *   result = lwm2m_ecdh_derive_aes_key(peer_public_key, our_private_key, derived_aes_key,
 *                                     (const uint8_t *)salt, strlen(salt),
 *                                     (const uint8_t *)info, strlen(info));
 *
 * Example usage for ChaCha20-Poly1305 encryption:
 *
 *   // Use derived key from ECDH or your own 32-byte key
 *   uint8_t key[32];         // 256-bit encryption key
 *   uint8_t nonce[12];       // 96-bit nonce (must be unique per encryption)
 *   uint8_t tag[16];         // 128-bit authentication tag
 *   
 *   const char *message = "Secret message";
 *   const char *aad = "Public header info";
 *   uint8_t ciphertext[256];
 *   uint8_t plaintext[256];
 *   
 *   // Generate a secure random nonce
 *   lwm2m_chacha20_generate_nonce(nonce);
 *   
 *   // Encrypt
 *   int result = lwm2m_chacha20_poly1305_encrypt(key, nonce,
 *                                               (uint8_t *)message, strlen(message),
 *                                               (uint8_t *)aad, strlen(aad),
 *                                               ciphertext, tag);
 *   if (result == 0) {
 *       // Send: nonce + ciphertext + tag (AAD sent separately)
 *   }
 *   
 *   // Decrypt
 *   result = lwm2m_chacha20_poly1305_decrypt(key, nonce,
 *                                           ciphertext, strlen(message),
 *                                           (uint8_t *)aad, strlen(aad),
 *                                           tag, plaintext);
 *   if (result == 0) {
 *       plaintext[strlen(message)] = '\0';  // null-terminate
 *       printf("Decrypted: %s\n", plaintext);
 *   }
 */

 int lwm2m_read_factory_partition(const uint8_t *buffer, const size_t buffer_len, lwm2m_FactoryPartition *partition);

/* ECDH AES key derivation function
 * Derives a 256-bit AES key using ECDH key exchange and HKDF
 * 
 * Parameters:
 *  - public_key: Peer's public key (65 bytes for uncompressed P-256)
 *  - private_key: Our private key (32 bytes for P-256)
 *  - derived_key: Output buffer for derived AES key (32 bytes)
 *  - salt: Optional salt for HKDF (can be NULL)
 *  - salt_len: Length of salt (0 if salt is NULL)
 *  - info: Optional context info for HKDF (can be NULL)
 *  - info_len: Length of info (0 if info is NULL)
 *
 * Return codes:
 *  0  success
 * -1  invalid arguments
 * -2  ECDH computation failure
 * -3  HKDF derivation failure
 */
int lwm2m_ecdh_derive_aes_key(const uint8_t *public_key, const uint8_t *private_key,
                              uint8_t *derived_key, const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len);

/* Helper function to derive AES key with default parameters (no salt/info)
 * Simplified version that uses empty salt and "LwM2M-AES-Key" as info
 */
int lwm2m_ecdh_derive_aes_key_simple(const uint8_t *public_key, const uint8_t *private_key,
                                     uint8_t *derived_key);

/* ChaCha20-Poly1305 encryption function
 * Encrypts data using ChaCha20-Poly1305 AEAD cipher
 * 
 * Parameters:
 *  - key: 32-byte encryption key
 *  - nonce: 12-byte nonce/IV (must be unique for each encryption with same key)
 *  - plaintext: Input data to encrypt
 *  - plaintext_len: Length of plaintext in bytes
 *  - aad: Additional authenticated data (can be NULL if aad_len is 0)
 *  - aad_len: Length of AAD in bytes
 *  - ciphertext: Output buffer for encrypted data (same size as plaintext)
 *  - tag: Output buffer for authentication tag (16 bytes)
 *
 * Return codes:
 *  0  success
 * -1  invalid arguments
 * -2  encryption failure
 */
int lwm2m_chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *plaintext, size_t plaintext_len,
                                    const uint8_t *aad, size_t aad_len,
                                    uint8_t *ciphertext, uint8_t *tag);

/* ChaCha20-Poly1305 decryption function
 * Decrypts data using ChaCha20-Poly1305 AEAD cipher
 * 
 * Parameters:
 *  - key: 32-byte decryption key (same as used for encryption)
 *  - nonce: 12-byte nonce/IV (same as used for encryption)
 *  - ciphertext: Input encrypted data
 *  - ciphertext_len: Length of ciphertext in bytes
 *  - aad: Additional authenticated data (same as used for encryption)
 *  - aad_len: Length of AAD in bytes
 *  - tag: Authentication tag from encryption (16 bytes)
 *  - plaintext: Output buffer for decrypted data (same size as ciphertext)
 *
 * Return codes:
 *  0  success
 * -1  invalid arguments
 * -2  decryption failure
 * -3  authentication failure (tag mismatch)
 */
int lwm2m_chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *ciphertext, size_t ciphertext_len,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *tag, uint8_t *plaintext);

/* Generate a secure random nonce for ChaCha20-Poly1305
 * Fills a 12-byte buffer with cryptographically secure random data
 * 
 * Parameters:
 *  - nonce: Output buffer for nonce (12 bytes)
 *
 * Return codes:
 *  0  success
 * -1  RNG failure
 */
int lwm2m_chacha20_generate_nonce(uint8_t *nonce);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LWM2M_HELPERS_H_ */
