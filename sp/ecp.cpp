#include "ecp.h"
#include <string.h>

// Minimal wrapper calling sample_libcrypto signature helper
sample_status_t sample_ecdsa_sign(const uint8_t *data, uint32_t data_size,
                                  const sample_ec_priv_t *p_priv_key,
                                  sample_ec_sign256_t *p_signature,
                                  sample_ecc_state_handle_t ecc_handle)
{
    if (!data || !p_priv_key || !p_signature)
        return SAMPLE_ERROR_INVALID_PARAMETER;

    // Reuse sample_libcrypto primitive
    return sample_ecdsa_sign(data, data_size, const_cast<sample_ec256_private_t *>(&p_priv_key->r), p_signature, ecc_handle);
}
