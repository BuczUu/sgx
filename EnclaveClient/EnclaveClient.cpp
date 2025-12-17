#include "EnclaveClient_t.h"

#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"

// This is the SP's public key for ECDH
// In real scenario, this would be the Service Provider's public key
// For testing, we use a sample key
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t *p_context)
{
    return sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
}

sgx_status_t enclave_ra_close(sgx_ra_context_t context)
{
    return sgx_ra_close(context);
}

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* message, 
                                   size_t message_size, 
                                   uint8_t* mac, 
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t sk_key;

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if(SGX_SUCCESS != ret)
    {
        return ret;
    }

    uint8_t aes_gcm_iv[12] = {0};
    
    sgx_rijndael128GCM_decrypt(&sk_key,
                               message,
                               message_size,
                               NULL,
                               aes_gcm_iv,
                               12,
                               NULL,
                               0,
                               (sgx_aes_gcm_128bit_tag_t*)mac);
    
    return ret;
}

sgx_status_t verify_server_mrenclave(sgx_ra_context_t context,
                                     uint8_t* received_mrenclave,
                                     uint8_t* expected_mrenclave,
                                     int* match)
{
    // Compare the two MRENCLAVEs
    *match = (memcmp(received_mrenclave, expected_mrenclave, 32) == 0) ? 1 : 0;
    return SGX_SUCCESS;
}
