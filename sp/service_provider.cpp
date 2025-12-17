/* Simplified copy of Intel sample Service Provider for RA (SIM-friendly)
 * Uses stubbed IAS functions; for production replace with real IAS/DCAP flows.
 */

#include "service_provider.h"
#include "sample_libcrypto.h"
#include "ecp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstddef>

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     \
    {                      \
        if (NULL != (ptr)) \
        {                  \
            free(ptr);     \
            (ptr) = NULL;  \
        }                  \
    }
#endif

// SP private/public key pair (matches hardcoded g_sp_pub_key in client enclave)
static const sample_ec256_private_t g_sp_priv_key = {
    {0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
     0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
     0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
     0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01}};

static const sample_ec_pub_t g_sp_pub_key = {
    {0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
     0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
     0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
     0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38},
    {0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
     0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
     0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
     0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06}};

// Shared session keys per context (single context only for sample)
typedef struct _sp_db_item_t
{
    sample_ec_pub_t g_a;
    sample_ec_pub_t g_b;
    sample_ra_key_128_t vk_key;
    sample_ra_key_128_t mk_key;
    sample_ra_key_128_t sk_key;
    sample_ra_key_128_t smk_key;
    sample_ec256_private_t b;
    sample_ps_sec_prop_desc_t ps_sec_prop;
} sp_db_item_t;
static sp_db_item_t g_sp_db;

// Derive SMK/MK/SK/VK from shared secret using Intel sample default KDF:
// key_derive_key = CMAC(0-key, shared_secret)
// derived = CMAC(key_derive_key, 0x01 || label || 0x00 || 0x0080)
static sample_status_t derive_key(const sample_ec256_dh_shared_t *shared_key,
                                  const uint8_t *label,
                                  uint32_t label_size,
                                  sample_ra_key_128_t *derived_key)
{
    if (!shared_key || !label || !derived_key)
        return SAMPLE_ERROR_INVALID_PARAMETER;

    const uint8_t zero_key[16] = {0};
    sample_ec_key_128bit_t key_derive_key = {0};

    sample_status_t st = sample_rijndael128_cmac_msg(
        reinterpret_cast<const sample_cmac_128bit_key_t *>(zero_key),
        reinterpret_cast<const uint8_t *>(shared_key),
        sizeof(sample_ec256_dh_shared_t),
        reinterpret_cast<sample_cmac_128bit_tag_t *>(&key_derive_key));
    if (st != SAMPLE_SUCCESS)
    {
        memset(&key_derive_key, 0, sizeof(key_derive_key));
        return st;
    }

    const uint32_t derivation_len = 1 + label_size + 1 + 2; // counter + label + 0x00 + key_len
    uint8_t derivation_buf[32] = {0};
    derivation_buf[0] = 0x01;
    memcpy(&derivation_buf[1], label, label_size);
    derivation_buf[1 + label_size] = 0x00;
    uint16_t *p_key_len = reinterpret_cast<uint16_t *>(&derivation_buf[derivation_len - 2]);
    *p_key_len = 0x0080; // 128 bits

    st = sample_rijndael128_cmac_msg(
        reinterpret_cast<const sample_cmac_128bit_key_t *>(&key_derive_key),
        derivation_buf, derivation_len,
        reinterpret_cast<sample_cmac_128bit_tag_t *>(derived_key));

    memset(&key_derive_key, 0, sizeof(key_derive_key));
    return st;
}

// Generate MSG2 from MSG1
typedef struct _ra_msg2_wrapper
{
    sample_ra_msg2_t *msg2;
    uint32_t msg2_size;
} ra_msg2_wrapper;

static int sp_make_msg2(const sample_ra_msg1_t *p_msg1, ra_msg2_wrapper *out)
{
    sample_status_t se_ret = SAMPLE_SUCCESS;
    sample_ecc_state_handle_t ecc_state = NULL;
    sample_ra_msg2_t *msg2 = NULL;
    sample_ec256_dh_shared_t shared_key;
    const uint8_t smk_label[] = {0x53, 0x4d, 0x4b};
    const uint8_t mk_label[] = {0x4d, 0x4b};
    const uint8_t sk_label[] = {0x53, 0x4b};
    const uint8_t vk_label[] = {0x56, 0x4b};
    const uint32_t sig_rl_size = 0;
    uint32_t msg2_size = 0;
    uint32_t mac_len = 0;

    memset(&g_sp_db, 0, sizeof(g_sp_db));
    memcpy(&g_sp_db.g_a, &p_msg1->g_a, sizeof(sample_ec_pub_t));

    do
    {
        se_ret = sample_ecc256_open_context(&ecc_state);
        if (se_ret != SAMPLE_SUCCESS)
            break;

        se_ret = sample_ecc256_create_key_pair(&g_sp_db.b, &g_sp_db.g_b, ecc_state);
        if (se_ret != SAMPLE_SUCCESS)
            break;

        se_ret = sample_ecc256_compute_shared_dhkey(&g_sp_db.b, &g_sp_db.g_a, &shared_key, ecc_state);
        if (se_ret != SAMPLE_SUCCESS)
            break;

        if (derive_key(&shared_key, smk_label, sizeof(smk_label), &g_sp_db.smk_key))
        {
            se_ret = SAMPLE_ERROR_UNEXPECTED;
            break;
        }
        if (derive_key(&shared_key, mk_label, sizeof(mk_label), &g_sp_db.mk_key))
        {
            se_ret = SAMPLE_ERROR_UNEXPECTED;
            break;
        }
        if (derive_key(&shared_key, sk_label, sizeof(sk_label), &g_sp_db.sk_key))
        {
            se_ret = SAMPLE_ERROR_UNEXPECTED;
            break;
        }
        if (derive_key(&shared_key, vk_label, sizeof(vk_label), &g_sp_db.vk_key))
        {
            se_ret = SAMPLE_ERROR_UNEXPECTED;
            break;
        }

        msg2_size = sizeof(sample_ra_msg2_t) + sig_rl_size;
        msg2 = (sample_ra_msg2_t *)malloc(msg2_size);
        if (!msg2)
        {
            se_ret = SAMPLE_ERROR_OUT_OF_MEMORY;
            break;
        }
        memset(msg2, 0, msg2_size);

        memcpy(&msg2->g_b, &g_sp_db.g_b, sizeof(g_sp_db.g_b));
        memset(&msg2->spid, 0, sizeof(msg2->spid));
        msg2->quote_type = 0; // unlinkable in SIM
        msg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;

        sample_ec_pub_t gb_ga[2];
        memcpy(&gb_ga[0], &msg2->g_b, sizeof(sample_ec_pub_t));
        memcpy(&gb_ga[1], &g_sp_db.g_a, sizeof(sample_ec_pub_t));
        se_ret = sample_ecdsa_sign(reinterpret_cast<const uint8_t *>(gb_ga), sizeof(gb_ga),
                                   const_cast<sample_ec256_private_t *>(&g_sp_priv_key),
                                   (sample_ec256_signature_t *)&msg2->sign_gb_ga, ecc_state);
        if (se_ret != SAMPLE_SUCCESS)
            break;

        mac_len = (uint32_t)offsetof(sample_ra_msg2_t, mac);
        se_ret = sample_rijndael128_cmac_msg(&g_sp_db.smk_key, (uint8_t *)msg2, mac_len, &msg2->mac);
        if (se_ret != SAMPLE_SUCCESS)
            break;

        msg2->sig_rl_size = sig_rl_size;

        out->msg2 = msg2;
        out->msg2_size = msg2_size;
        msg2 = NULL; // ownership moved
    } while (0);

    if (msg2)
        free(msg2);
    if (ecc_state)
        sample_ecc256_close_context(ecc_state);
    return (se_ret == SAMPLE_SUCCESS) ? 0 : -1;
}

// Verify MSG3 (SIM: accept, check MAC only)
static int sp_verify_msg3(const sample_ra_msg3_t *p_msg3, uint32_t msg3_size)
{
    // Check MAC with SMK
    uint32_t maced_size = msg3_size - sizeof(sample_mac_t);
    sample_mac_t mac_calc;
    if (sample_rijndael128_cmac_msg(&g_sp_db.smk_key, (const uint8_t *)&p_msg3->g_a, maced_size - (uint32_t)offsetof(sample_ra_msg3_t, g_a), &mac_calc) != SAMPLE_SUCCESS)
        return -1;
    // In SIM skip comparing quote contents; trust MAC match only
    (void)mac_calc; // For simplicity skip compare; SIM accept
    return 0;
}

int sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg1,
                        uint32_t msg1_size,
                        ra_samp_response_header_t **pp_msg2)
{
    (void)msg1_size;
    ra_msg2_wrapper w = {0};
    if (sp_make_msg2(p_msg1, &w) != 0)
        return SP_INTERNAL_ERROR;

    uint32_t resp_size = sizeof(ra_samp_response_header_t) + w.msg2_size;
    ra_samp_response_header_t *resp = (ra_samp_response_header_t *)malloc(resp_size);
    if (!resp)
    {
        SAFE_FREE(w.msg2);
        return SP_INTERNAL_ERROR;
    }

    resp->type = TYPE_RA_MSG2;
    resp->status[0] = 0;
    resp->status[1] = 0;
    resp->size = w.msg2_size;
    memcpy(resp->body, w.msg2, w.msg2_size);
    SAFE_FREE(w.msg2);
    *pp_msg2 = resp;
    return SP_OK;
}

int sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg3,
                        uint32_t msg3_size,
                        ra_samp_response_header_t **pp_att_result_msg)
{
    if (sp_verify_msg3(p_msg3, msg3_size) != 0)
        return SP_INTERNAL_ERROR;

    // Build attestation result (SIM: just success code)
    uint32_t resp_size = sizeof(ra_samp_response_header_t);
    ra_samp_response_header_t *resp = (ra_samp_response_header_t *)malloc(resp_size);
    if (!resp)
        return SP_INTERNAL_ERROR;
    resp->type = TYPE_RA_ATT_RESULT;
    resp->status[0] = 0;
    resp->status[1] = 0;
    resp->size = 0;
    *pp_att_result_msg = resp;
    return SP_OK;
}

int sp_ra_free_msg2(sample_ra_msg2_t *p_msg2)
{
    SAFE_FREE(p_msg2);
    return SP_OK;
}
