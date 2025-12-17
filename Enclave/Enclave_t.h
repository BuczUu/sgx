#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t get_enclave_report(const sgx_target_info_t* target_info, sgx_report_t* report);
sgx_status_t get_session_key(sgx_ra_context_t context, uint8_t* sk_key);
sgx_status_t encrypt_psi_result(sgx_ra_context_t context, const uint32_t* result, uint32_t result_count, uint8_t* encrypted_data, uint32_t encrypted_size, uint8_t* gcm_mac);
sgx_status_t decrypt_client_data(sgx_ra_context_t context, const uint8_t* encrypted_data, uint32_t encrypted_size, const uint8_t* gcm_mac, uint32_t* decrypted_set, uint32_t* set_size);
sgx_status_t ecall_compute_psi_count(const uint32_t* set1, const uint32_t* set2, uint32_t* result, uint32_t* result_count);
sgx_status_t ecall_register_client_set(uint32_t client_id, const uint32_t* set, uint32_t set_size);
sgx_status_t ecall_compute_psi_multi(uint32_t* result, uint32_t* result_count);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
