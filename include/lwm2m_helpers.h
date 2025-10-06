#ifndef LWM2M_HELPERS_H_
#define LWM2M_HELPERS_H_

#include <stddef.h>
#include <stdint.h>
#include "lwm2m.pb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Helper function declarations can be added here.
 * Example (remove when adding real APIs):
 * bool lwm2m_encode_uint32(uint32_t value, uint8_t *buffer, size_t buffer_len, size_t *encoded_len);
 */

 int lwm2m_read_factory_partition(const uint8_t *buffer, const size_t buffer_len, lwm2m_FactoryPartition *partition);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LWM2M_HELPERS_H_ */
