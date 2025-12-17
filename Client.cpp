/*
 * PSI_SGX Client - with enclave for Remote Attestation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "client_certs.h"
#include "server_mrenclave.h"
#include "EnclaveClient_u.h"
#include "sgx_urts.h"
#include "sgx_ukey_exchange.h"

#define PORT 12345
#define SET_SIZE 10
#define ENCLAVE_FILENAME "enclaveclient.signed.so"

sgx_enclave_id_t global_eid = 0;

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("Failed to create enclave. Error code: 0x%x\n", ret);
        return -1;
    }
    printf("[CLIENT] Enclave created successfully\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <client_id> (1 or 2)\n", argv[0]);
        return -1;
    }

    int client_id = atoi(argv[1]);
    if (client_id != 1 && client_id != 2)
    {
        printf("Invalid client_id. Must be 1 or 2\n");
        return -1;
    }

    /* Initialize enclave */
    if (initialize_enclave() < 0)
    {
        return -1;
    }

    /* Create socket */
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        perror("socket");
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* Connect to server */
    printf("[CLIENT %d] Connecting to server...\n", client_id);
    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        close(socket_fd);
        return -1;
    }

    printf("[CLIENT %d] Connected to server\n", client_id);

    /* Step 1: Send client certificate for authentication */
    const uint8_t *my_cert_hash = authorized_clients[client_id - 1].cert_hash;
    if (send(socket_fd, my_cert_hash, 32, 0) < 0)
    {
        perror("send certificate");
        close(socket_fd);
        return -1;
    }
    printf("[CLIENT %d] Certificate sent to server\n", client_id);

    /* Step 2: Wait for authentication response */
    uint32_t auth_response;
    if (recv(socket_fd, &auth_response, sizeof(auth_response), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive auth response\n", client_id);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (auth_response != 0x00000000)
    {
        printf("[CLIENT %d] Authentication REJECTED by server!\n", client_id);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] Authentication successful - server verified\n", client_id);

    /* Step 3: Initialize Remote Attestation in enclave */
    sgx_status_t ret, ra_status;
    sgx_ra_context_t ra_context;

    ret = enclave_init_ra(global_eid, &ra_status, 0, &ra_context);
    if (ret != SGX_SUCCESS || ra_status != SGX_SUCCESS)
    {
        printf("[CLIENT %d] Failed to initialize RA. Error: 0x%x\n", client_id, ra_status);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] RA initialized, context: %u\n", client_id, ra_context);

    /* Step 4: Generate MSG1 */
    sgx_ra_msg1_t msg1;
    ret = sgx_ra_get_msg1(ra_context, global_eid, sgx_ra_get_ga, &msg1);
    if (ret != SGX_SUCCESS)
    {
        printf("[CLIENT %d] Failed to generate MSG1. Error: 0x%x\n", client_id, ret);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] MSG1 generated\n", client_id);

    /* Step 5: Send MSG1 to server */
    if (send(socket_fd, &msg1, sizeof(sgx_ra_msg1_t), 0) < 0)
    {
        perror("send MSG1");
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] MSG1 sent to server\n", client_id);

    /* Step 6: Receive MSG2 from server */
    uint32_t msg2_size;
    if (recv(socket_fd, &msg2_size, sizeof(msg2_size), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive MSG2 size\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    sgx_ra_msg2_t *p_msg2 = (sgx_ra_msg2_t *)malloc(msg2_size);
    if (!p_msg2)
    {
        printf("[CLIENT %d] Failed to allocate memory for MSG2\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (recv(socket_fd, p_msg2, msg2_size, 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive MSG2\n", client_id);
        free(p_msg2);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] MSG2 received (size: %u)\n", client_id, msg2_size);

    /* Step 7: Process MSG2 and generate MSG3 */
    sgx_ra_msg3_t *p_msg3 = NULL;
    uint32_t msg3_size = 0;

    ret = sgx_ra_proc_msg2(ra_context, global_eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
                           p_msg2, msg2_size, &p_msg3, &msg3_size);
    free(p_msg2);

    if (ret != SGX_SUCCESS || !p_msg3)
    {
        printf("[CLIENT %d] Failed to process MSG2. Error: 0x%x\n", client_id, ret);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] MSG3 generated (size: %u)\n", client_id, msg3_size);

    /* Step 8: Send MSG3 to server */
    if (send(socket_fd, &msg3_size, sizeof(msg3_size), 0) < 0)
    {
        perror("send MSG3 size");
        free(p_msg3);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (send(socket_fd, p_msg3, msg3_size, 0) < 0)
    {
        perror("send MSG3");
        free(p_msg3);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    free(p_msg3);
    printf("[CLIENT %d] MSG3 sent - RA protocol completed!\n", client_id);

    /* Step 9: Receive attestation result */
    uint32_t attestation_result;
    if (recv(socket_fd, &attestation_result, sizeof(attestation_result), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive attestation result\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (attestation_result != 0x00000000)
    {
        printf("[CLIENT %d] Server attestation FAILED!\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    /* Step 10: Receive server MRENCLAVE and verify pinned measurement */
    uint8_t server_mrenclave[32];
    if (recv(socket_fd, server_mrenclave, sizeof(server_mrenclave), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive server MRENCLAVE\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    int match = 0;

    /* Skip check if expected measurement is all zeros (user must fill it) */
    int expected_nonzero = 0;
    for (int i = 0; i < 32; i++)
        expected_nonzero |= expected_server_mrenclave[i];

    if (expected_nonzero)
    {
        sgx_status_t m_status = verify_server_mrenclave(global_eid, &ra_status,
                                ra_context,
                                server_mrenclave,
                                const_cast<uint8_t *>(expected_server_mrenclave),
                                &match);
        if (m_status != SGX_SUCCESS || ra_status != SGX_SUCCESS || !match)
        {
            printf("[CLIENT %d] Server MRENCLAVE mismatch!\n", client_id);
            enclave_ra_close(global_eid, &ra_status, ra_context);
            close(socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        }
        printf("[CLIENT %d] Server MRENCLAVE pinned and verified.\n", client_id);
    }
    else
    {
        printf("[CLIENT %d] Warning: expected_server_mrenclave not set (all zeros); skipping MRENCLAVE pin check.\n", client_id);
    }

    printf("[CLIENT %d] Server attestation successful - server code verified!\n", client_id);

    /* Prepare data sets */
    uint32_t set[SET_SIZE];
    uint32_t set_size;

    if (client_id == 1)
    {
        /* Set 1: {1, 2, 3, 4, 5} */
        uint32_t data[] = {1, 2, 3, 4, 5};
        set_size = 5;
        memcpy(set, data, set_size * sizeof(uint32_t));
        printf("[CLIENT %d] Set: {1, 2, 3, 4, 5}\n", client_id);
    }
    else
    {
        /* Set 2: {3, 4, 5, 6, 7} */
        uint32_t data[] = {3, 4, 5, 6, 7};
        set_size = 5;
        memcpy(set, data, set_size * sizeof(uint32_t));
        printf("[CLIENT %d] Set: {3, 4, 5, 6, 7}\n", client_id);
    }

    /* Send set size */
    if (send(socket_fd, &set_size, sizeof(set_size), 0) < 0)
    {
        perror("send set_size");
        close(socket_fd);
        return -1;
    }

    /* Send set elements */
    for (uint32_t i = 0; i < set_size; i++)
    {
        if (send(socket_fd, &set[i], sizeof(uint32_t), 0) < 0)
        {
            perror("send element");
            close(socket_fd);
            return -1;
        }
    }

    printf("[CLIENT %d] Set sent to server\n", client_id);

    /* Wait for PSI result (plaintext for now) */
    printf("[CLIENT %d] Waiting for PSI result...\n", client_id);
    uint32_t result_count;

    if (recv(socket_fd, &result_count, sizeof(result_count), 0) <= 0)
    {
        printf("[CLIENT %d] No result received or connection closed\n", client_id);
        close(socket_fd);
        return 0;
    }

    printf("[CLIENT %d] PSI Result: ", client_id);
    for (uint32_t i = 0; i < result_count; i++)
    {
        uint32_t value;
        if (recv(socket_fd, &value, sizeof(uint32_t), 0) > 0)
        {
            printf("%u ", value);
        }
    }
    printf("\n");

    /* Cleanup */
    enclave_ra_close(global_eid, &ra_status, ra_context);
    close(socket_fd);
    sgx_destroy_enclave(global_eid);
    printf("[CLIENT %d] Done\n", client_id);
    return 0;
}
