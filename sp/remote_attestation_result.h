#pragma once
#include <stdint.h>

// Minimal copy from Intel sample: message headers for RA responses

typedef enum
{
    TYPE_RA_MSG0 = 0,
    TYPE_RA_MSG1 = 1,
    TYPE_RA_MSG2 = 2,
    TYPE_RA_MSG3 = 3,
    TYPE_RA_ATT_RESULT = 4,
} ra_msg_type_t;

#pragma pack(push, 1)
typedef struct _ra_samp_response_header_t
{
    uint8_t type;      // ra_msg_type_t
    uint8_t status[2]; // unused in SIM flow
    uint32_t size;     // size of the body in bytes
    uint8_t body[];    // flexible array member
} ra_samp_response_header_t;
#pragma pack(pop)
