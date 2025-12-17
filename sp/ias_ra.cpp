#include "ias_ra.h"
#include <stdlib.h>
#include <string.h>

// Stubs for SIM: always succeed, no network/IAS

int ias_enroll(int, sample_spid_t *spid, int *auth_token)
{
    if (spid)
        memset(spid, 0, sizeof(sample_spid_t));
    if (auth_token)
        *auth_token = 0;
    return 0;
}

int ias_get_sigrl(const sample_epid_group_id_t, uint32_t *p_sig_rl_size, uint8_t **p_sig_rl)
{
    if (p_sig_rl_size)
        *p_sig_rl_size = 0;
    if (p_sig_rl)
        *p_sig_rl = NULL;
    return 0;
}

int ias_verify_attestation_evidence(const sample_quote_t *, uint8_t *, ias_att_report_t *att_report)
{
    if (att_report)
    {
        att_report->id = 0;
        att_report->status = IAS_QUOTE_OK;
    }
    return 0; // success
}
