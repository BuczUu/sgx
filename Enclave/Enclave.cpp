#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_utils.h"

/* Multi-client PSI state */
static uint32_t client1_set[10] = {0};
static uint32_t client1_size = 0;
static uint32_t client2_set[10] = {0};
static uint32_t client2_size = 0;
static uint32_t clients_registered = 0;

/* Service Provider's public key - hardcoded for RA */
static const sgx_ec256_public_t g_sp_pub_key = {
    {0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
     0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
     0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
     0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38},
    {0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
     0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
     0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
     0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06}};

/* Hardcoded session key for SIM mode (since sgx_ra_get_keys doesn't work in SIM)
 * In HW mode, this would be derived from ECDH key exchange */
static const sgx_ec_key_128bit_t g_sim_session_key = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

/* printf wrapper for enclave */
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

/* Remote Attestation Functions */

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t *p_context)
{
    sgx_status_t ret;
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
    printf("[ENCLAVE] RA initialized, context: %u\n", *p_context);
    return ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    printf("[ENCLAVE] RA context closed: %u\n", context);
    return ret;
}

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t *p_message,
                                   size_t message_size,
                                   uint8_t *p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if (mac_size != sizeof(sgx_mac_t))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (message_size > UINT32_MAX)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
    if (SGX_SUCCESS != ret)
    {
        return ret;
    }

    sgx_mac_t mac;
    ret = sgx_rijndael128_cmac_msg(&mk_key,
                                   p_message,
                                   (uint32_t)message_size,
                                   &mac);
    if (SGX_SUCCESS != ret)
    {
        return ret;
    }

    if (0 == consttime_memequal(p_mac, mac, sizeof(mac)))
    {
        return SGX_ERROR_MAC_MISMATCH;
    }

    printf("[ENCLAVE] Attestation result MAC verified\n");
    return SGX_SUCCESS;
}

sgx_status_t get_enclave_report(const sgx_target_info_t *target_info,
                                sgx_report_t *report)
{
    sgx_report_data_t report_data = {0};
    sgx_status_t ret = sgx_create_report(target_info, &report_data, report);
    printf("[ENCLAVE] Created report\n");
    return ret;
}

/* Get session key (SK) from RA context */
sgx_status_t get_session_key(sgx_ra_context_t context, uint8_t *sk_key)
{
    if (!sk_key)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_ec_key_128bit_t key;
    sgx_status_t ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &key);
    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] Failed to get SK key: 0x%x\n", ret);
        return ret;
    }

    memcpy(sk_key, &key, 16);
    printf("[ENCLAVE] Session key retrieved\n");
    return SGX_SUCCESS;
}

/* Encrypt PSI result using AES-GCM with SK key */
sgx_status_t encrypt_psi_result(sgx_ra_context_t context,
                                const uint32_t *result,
                                uint32_t result_count,
                                uint8_t *encrypted_data,
                                uint32_t encrypted_size,
                                uint8_t *gcm_mac)
{
    if (!result || !encrypted_data || !gcm_mac)
        return SGX_ERROR_INVALID_PARAMETER;

    if (encrypted_size < result_count * sizeof(uint32_t))
        return SGX_ERROR_INVALID_PARAMETER;

    /* Get SK key from RA context */
    sgx_ec_key_128bit_t sk_key;
    sgx_status_t ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] Failed to get SK key for encryption: 0x%x\n", ret);
        return ret;
    }

    /* Initialize IV to zeros (should be random in production) */
    uint8_t aes_gcm_iv[12] = {0};

    /* Encrypt using AES-GCM */
    ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                     (const uint8_t *)result,
                                     result_count * sizeof(uint32_t),
                                     encrypted_data,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     (sgx_aes_gcm_128bit_tag_t *)gcm_mac);

    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] AES-GCM encryption failed: 0x%x\n", ret);
        return ret;
    }

    printf("[ENCLAVE] PSI result encrypted (%u bytes)\n", result_count * sizeof(uint32_t));
    return SGX_SUCCESS;
}

/* Decrypt client data using AES-GCM with SK key */
sgx_status_t decrypt_client_data(sgx_ra_context_t context,
                                 const uint8_t *encrypted_data,
                                 uint32_t encrypted_size,
                                 const uint8_t *gcm_mac,
                                 uint32_t *decrypted_set,
                                 uint32_t *set_size)
{
    if (!encrypted_data || !gcm_mac || !decrypted_set || !set_size)
        return SGX_ERROR_INVALID_PARAMETER;

    /* Get SK key from RA context */
    sgx_ec_key_128bit_t sk_key;
    sgx_status_t ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] Failed to get SK key for decryption: 0x%x\n", ret);
        return ret;
    }

    /* Initialize IV to zeros (must match encryption) */
    uint8_t aes_gcm_iv[12] = {0};

    /* Decrypt using AES-GCM */
    ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                     encrypted_data,
                                     encrypted_size,
                                     (uint8_t *)decrypted_set,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t *)gcm_mac);

    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] AES-GCM decryption failed: 0x%x\n", ret);
        return ret;
    }

    *set_size = encrypted_size / sizeof(uint32_t);
    printf("[ENCLAVE] Client data decrypted (%u elements)\n", *set_size);
    return SGX_SUCCESS;
}

/* Register client set */
sgx_status_t ecall_register_client_set(uint32_t client_id, const uint32_t *set, uint32_t set_size)
{
    if (!set || set_size == 0 || set_size > 10)
        return SGX_ERROR_INVALID_PARAMETER;

    if (client_id == 1)
    {
        memcpy(client1_set, set, set_size * sizeof(uint32_t));
        client1_size = set_size;
        printf("[ENCLAVE] Client 1 registered set of size %u\n", set_size);
    }
    else if (client_id == 2)
    {
        memcpy(client2_set, set, set_size * sizeof(uint32_t));
        client2_size = set_size;
        printf("[ENCLAVE] Client 2 registered set of size %u\n", set_size);
    }
    else
        return SGX_ERROR_INVALID_PARAMETER;

    clients_registered++;
    return SGX_SUCCESS;
}

/* Compute PSI intersection */
sgx_status_t ecall_compute_psi_multi(uint32_t *result, uint32_t *result_count)
{
    if (!result || !result_count || clients_registered != 2)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t count = 0;

    for (uint32_t i = 0; i < client1_size && count < 10; i++)
    {
        for (uint32_t j = 0; j < client2_size; j++)
        {
            if (client1_set[i] == client2_set[j])
            {
                result[count++] = client1_set[i];
                break;
            }
        }
    }

    *result_count = count;
    printf("[ENCLAVE] Multi-client PSI: intersection size = %u\n", count);
    return SGX_SUCCESS;
}

/* Single-client PSI mode */
sgx_status_t ecall_compute_psi_count(
    const uint32_t *set1,
    const uint32_t *set2,
    uint32_t *result,
    uint32_t *result_count)
{
    if (!set1 || !set2 || !result || !result_count)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t count = 0;

    for (int i = 0; i < 5; i++)
    {
        for (int j = 0; j < 5; j++)
        {
            if (set1[i] == set2[j])
            {
                result[count++] = set1[i];
                break;
            }
        }
    }

    *result_count = count;
    printf("[ENCLAVE] PSI computed: intersection size = %u\n", count);
    return SGX_SUCCESS;
}