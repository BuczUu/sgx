#pragma once

#include "sample_libcrypto.h"
#include "remote_attestation_result.h"
#include "ias_ra.h"
#include "network_ra.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        SP_OK,
        SP_UNSUPPORTED_EXTENDED_EPID_GROUP,
        SP_INTEGRITY_FAILED,
        SP_QUOTE_VERIFICATION_FAILED,
        SP_IAS_FAILED,
        SP_INTERNAL_ERROR,
        SP_PROTOCOL_ERROR,
        SP_QUOTE_VERSION_ERROR,
    } sp_ra_msg_status_t;

#pragma pack(push, 1)
#define SAMPLE_SP_TAG_SIZE 16
#define SAMPLE_SP_IV_SIZE 12

    typedef sample_ec256_public_t sample_ec_pub_t;

    typedef struct sample_ps_sec_prop_desc_t
    {
        uint8_t sample_ps_sec_prop_desc[256];
    } sample_ps_sec_prop_desc_t;

#pragma pack(pop)

    typedef uint32_t sample_ra_context_t;
    typedef uint8_t sample_key_128bit_t[16];
    typedef sample_key_128bit_t sample_ra_key_128_t;

    typedef struct sample_ra_msg0_t
    {
        uint32_t extended_epid_group_id;
    } sample_ra_msg0_t;

    typedef struct sample_ra_msg1_t
    {
        sample_ec_pub_t g_a;
        sample_epid_group_id_t gid;
    } sample_ra_msg1_t;

    const uint16_t SAMPLE_AES_CMAC_KDF_ID = 0x0001;

    typedef struct sample_ra_msg2_t
    {
        sample_ec_pub_t g_b;
        sample_spid_t spid;
        uint16_t quote_type;
        uint16_t kdf_id;
        sample_ec_sign256_t sign_gb_ga;
        sample_mac_t mac;
        uint32_t sig_rl_size;
        uint8_t sig_rl[];
    } sample_ra_msg2_t;

    typedef struct sample_ra_msg3_t
    {
        sample_mac_t mac;
        sample_ec_pub_t g_a;
        sample_ps_sec_prop_desc_t ps_sec_prop;
        uint8_t quote[];
    } sample_ra_msg3_t;

    int sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg1,
                            uint32_t msg1_size,
                            ra_samp_response_header_t **pp_msg2);

    int sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg3,
                            uint32_t msg3_size,
                            ra_samp_response_header_t **pp_att_result_msg);

    int sp_ra_free_msg2(sample_ra_msg2_t *p_msg2);

#ifdef __cplusplus
}
#endif
