// Helper utilities implementation
//
// This file provides decoding helpers and related utility functions for the
// statically sized nanopb generated messages.

#include "lwm2m_helpers.h"
#include <pb_decode.h>
#include <string.h>

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



	/* signature is fixed length (64) per .options: ensure fully populated */
	if (sizeof(partition->signature) != 64) {
		return -3; /* compile-time mismatch */
	}



	return 0; /* success */
}

