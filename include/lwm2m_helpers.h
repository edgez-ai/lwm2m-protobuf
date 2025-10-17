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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LWM2M_HELPERS_H_ */
