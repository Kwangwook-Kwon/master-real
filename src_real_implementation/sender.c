#define _GNU_SOURCE
#include <infiniband/verbs.h>
#include <infiniband/verbs_exp.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <stdint.h>
#include <pthread.h>
#include <math.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "header.h"
#include "sender.h"

void create_data_packet(void *buf, bool ack)
{
    // Ether header
    struct ethhdr *eth = (struct ethhdr *)buf;
    memcpy(eth->h_dest, g_dst_mac_addr, ETH_ALEN);
    memcpy(eth->h_source, g_src_mac_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_8021Q);

    //VLAN header
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    vlan->h_vlan_TCI = htons(g_vlan_hdr);
    vlan->h_vlan_encapsulated_proto = htons(ETH_P_IP);

    //IP header
    struct iphdr *ip = (struct iphdr *)(vlan + 1);
    size_t ip_len = DATA_PACKET_SIZE - sizeof(struct ethhdr) - sizeof(struct vlan_hdr);
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 65;
    ip->tot_len = htons((uint16_t)ip_len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    memcpy(&ip->saddr, g_src_ip, 4);
    memcpy(&ip->daddr, g_dst_ip, 4);
    ip->check = gen_ip_checksum((char *)ip, sizeof(struct iphdr));

    //LCC Header
    struct lcchdr *lcc = (struct lcchdr *)(ip + 1);
    memset(lcc, 0, sizeof(struct lcchdr));
    size_t lcc_len = ip_len - sizeof(struct iphdr);
    lcc->source = UDP_SRC;
    lcc->dest = UDP_DST;
    lcc->len = htons((uint16_t)lcc_len);
    lcc->check = 0; //Zero means no checksum check at revciever
    lcc->data = 1;
    lcc->seq = g_send_seq;
    if (ack == true)
        lcc->ackReq = 1;
    g_send_seq++;

    // Payload : Data150
    void *payload = lcc + 1;
    char D = 'D';
    memset(payload, D, lcc_len - sizeof(struct lcchdr));
}

void create_dummy_packet(void *buf)
{
    // Ether header
    struct ethhdr *eth = (struct ethhdr *)buf;
    memcpy(eth->h_dest, g_brd_mac_addr, ETH_ALEN);
    memcpy(eth->h_source, g_src_mac_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    struct arphdr *arp = (struct arphdr *)(eth + 1);
    arp->ar_hrd = 0x0001;
    arp->ar_pro = 0x0800;
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op = 0x0001;

    memcpy(arp->ar_sha, g_src_mac_addr, ETH_ALEN);
    memcpy(arp->ar_sip, g_src_ip, 4);
    memcpy(arp->ar_tha, g_brd_mac_addr, ETH_ALEN);
    memcpy(arp->ar_tip, g_src_ip, 4);
}

void create_send_work_request(struct ibv_send_wr *wr, struct ibv_sge *sg_entry, struct ibv_mr *mr, void *buf, uint64_t wr_id, enum Packet_type packet_type)
{
    /* scatter/gather entry describes location and size of data to send*/
    sg_entry->addr = (uint64_t)buf;
    if (packet_type == DATA)
        sg_entry->length = DATA_PACKET_SIZE;
    else if (packet_type == DUMMY)
        sg_entry->length = 60;
    sg_entry->lkey = mr->lkey;
    memset(wr, 0, sizeof(struct ibv_send_wr));
    /*
     * descriptor for send transaction - details:
     * - how many pointer to data to use
     * - if this is a single descriptor or a list (next == NULL single)
     * - if we want inline and/or completion
     */

    wr->num_sge = 1;
    wr->sg_list = sg_entry;
    wr->next = NULL;
    wr->opcode = IBV_WR_SEND;
    wr->send_flags = IBV_SEND_SIGNALED;
    wr->wr_id = wr_id;
}

void create_recv_work_request(struct ibv_qp *qp, struct ibv_recv_wr *wr, struct ibv_sge *sg_entry, struct ibv_mr *mr, void *buf, struct raw_eth_flow_attr *flow_attr)
{
    struct ibv_recv_wr *bad_wr;
    /* pointer to packet buffer size and memory key of each packet buffer */
    sg_entry->length = ENTRY_SIZE;
    sg_entry->lkey = mr->lkey;
    /*
    * descriptor for receive transaction - details:
    * - how many pointers to receive buffers to use
    * - if this is a single descriptor or a list (next == NULL single)
    */

    wr->num_sge = 1;
    wr->sg_list = sg_entry;
    wr->next = NULL;
    for (int n = 0; n < RQ_NUM_DESC; n++)
    {
        /* each descriptor points to max MTU size buffer */
        sg_entry->addr = (uint64_t)buf + ENTRY_SIZE * n;

        /* index of descriptor returned when packet arrives */
        wr->wr_id = n;

        ibv_post_recv(qp, wr, &bad_wr);
    }
}

static uint16_t gen_ip_checksum(const char *buf, int num_bytes)
{
    const uint16_t *half_words = (const uint16_t *)buf;
    unsigned sum = 0;
    for (int i = 0; i < num_bytes / 2; i++)
        sum += half_words[i];

    if (num_bytes & 1)
        sum += buf[num_bytes - 1];

    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum & 0xff0000) >> 16;
    sum = ~sum & 0xffff;

    return sum;
}

void *clock_thread_function()
{

    unsigned long mask = 2;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }
    struct timespec time;
    time.tv_sec = 0;
    time.tv_nsec = 0;

    while (1)
    {
        clock_gettime(CLOCK_MONOTONIC, &time);
        g_time = time.tv_nsec;
    }
}

void *send_thread_fucntion(void *thread_arg)
{
    struct Thread_arg *args = (struct Thread_arg *)thread_arg;
    int thread_id = args->thread_id;
    int thread_action = args->thread_action;
    unsigned long mask = 4;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }

    int ret;
    /* 1. Create Complition Queue (CQ) */

    struct ibv_exp_values values = {0};
    ibv_exp_query_values(context, IBV_EXP_VALUES_CLOCK_INFO, &values);

    struct ibv_cq *cq_send;
    struct ibv_cq *cq_recv;
    struct ibv_exp_cq_init_attr cq_init_attr;

    memset(&cq_init_attr, 0, sizeof(cq_init_attr));
    cq_init_attr.flags = IBV_EXP_CQ_TIMESTAMP;
    cq_init_attr.comp_mask = IBV_EXP_CQ_INIT_ATTR_FLAGS;
    cq_send = ibv_exp_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0, &cq_init_attr);
    cq_recv = ibv_create_cq(context, RQ_NUM_DESC, NULL, NULL, 0);
    if (!cq_send || !cq_recv)
    {
        fprintf(stderr, "Couldn't create CQ %d\n", errno);
        exit(1);
    }

    /* 2. Initialize QP */
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_context = NULL,
        /* report send completion to cq */
        .send_cq = cq_send,
        .recv_cq = cq_recv,
        .cap = {
            /* number of allowed outstanding sends without waiting for a completion */
            .max_send_wr = SQ_NUM_DESC,
            .max_recv_wr = RQ_NUM_DESC,
            /* maximum number of pointers in each descriptor */
            .max_send_sge = 1,
            .max_recv_sge = 1,
        },
        .qp_type = IBV_QPT_RAW_PACKET,
    };

    /* 3. Create Queue Pair (QP) - Work request Ring */
    qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp)
    {
        fprintf(stderr, "Couldn't create RSS QP\n");
        exit(1);
    }

    /* 4. Initialize the QP (receive ring) and assign a port */
    struct ibv_qp_attr qp_attr;
    int qp_flags;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_flags = IBV_QP_STATE | IBV_QP_PORT;
    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.port_num = 1;
    ret = ibv_modify_qp(qp, &qp_attr, qp_flags);
    if (ret < 0)
    {
        fprintf(stderr, "failed modify qp to init\n");
        exit(1);
    }

    memset(&qp_attr, 0, sizeof(qp_attr));

    /* 5. Move the ring to ready to send in two steps (a,b) */
    /* a. Move ring state to ready to receive, this is needed to be able to move ring to ready to send even if receive queue is not enabled */
    qp_flags = IBV_QP_STATE;
    qp_attr.qp_state = IBV_QPS_RTR;
    ret = ibv_modify_qp(qp, &qp_attr, qp_flags);
    if (ret < 0)
    {
        fprintf(stderr, "failed modify qp to receive\n");
        exit(1);
    }

    /* b. Move the ring to ready to send */
    qp_flags = IBV_QP_STATE;
    qp_attr.qp_state = IBV_QPS_RTS;
    ret = ibv_modify_qp(qp, &qp_attr, qp_flags);
    if (ret < 0)
    {
        fprintf(stderr, "failed modify qp to receive\n");
        exit(1);
    }

    /* 9. Allocate Memory for send packet */
    void *buf_send; //sending buffer address
    void *buf_recv; //recving buffer address
    buf_send = malloc(buf_size_send);
    buf_recv = malloc(buf_size_recv);
    if (!buf_send || !buf_recv)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr_send;
    struct ibv_mr *mr_recv;
    mr_send = ibv_reg_mr(pd, buf_send, buf_size_send, IBV_ACCESS_LOCAL_WRITE);
    mr_recv = ibv_reg_mr(pd, buf_recv, buf_size_recv, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_send || !mr_recv)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    //Work request(WR)
    struct ibv_sge sg_entry_send[SQ_NUM_DESC];
    struct ibv_sge sg_entry_recv;
    struct ibv_send_wr wr_send[SQ_NUM_DESC], *bad_wr_send;
    struct ibv_recv_wr wr_recv, *bad_wr_recv;
    struct ibv_wc wc;
    struct ibv_exp_wc wc_exp_send;

    for (uint64_t i = 0; i < SQ_NUM_DESC; i++)
    {
        create_dummy_packet(buf_send + i * ENTRY_SIZE);
        create_send_work_request(wr_send + i, sg_entry_send + i, mr_send, buf_send + i * ENTRY_SIZE, i, DUMMY);
        ret = ibv_post_send(qp, wr_send + i, &bad_wr_send);

        if (ret < 0)
        {
            fprintf(stderr, "failed in post send\n");
            exit(1);
        }
    }

    uint64_t wr_id = 0;
    int msgs_completed_send = 0;
    int msgs_completed_recv;
    long time_taken = 0;
    long time_start, time_prev;
    double time_diff = 0;
    long send_time;
    int ack_tag = g_ack_req_inv - 1;
    g_time_require = (double)DATA_PACKET_SIZE * 8.0 / (g_init_rate / NUM_SEND_THREAD);
    g_prev_rate = g_init_rate;
    g_send_rate = g_init_rate;

    time_prev = g_time;

    //Sending procedure Loop
    printf("\n SEND Thread %d Loop Started\n", thread_id);
    printf("\ntime require: %ld\n", g_time_require);
    pthread_mutex_lock(&mutex_sender_thread);

    while (1)
    {
        time_start = g_time;
        if (time_start >= time_prev)
            time_taken += MIN((time_start - time_prev), SEND_BUCKET_LIMIT);
        else
            time_taken += MIN((time_start + 1 * 1e9 - time_prev), SEND_BUCKET_LIMIT);
        time_prev = time_start;

        if (time_taken >= g_time_require && msgs_completed_send > 0)
        {
            //printf("wr+id: %d\n", wr_id);
            ret = ibv_post_send(qp, wr_send + wr_id, &bad_wr_send);
            send_time = g_time;
            if (ret < 0)
            {
                fprintf(stderr, "failed in post send\n");
                exit(1);
            }

            if (2 * g_rtt_app > g_time_require * g_ack_req_inv)
                g_ack_req_inv += 8;
            else if (2.5 * g_rtt_app < g_time_require * g_ack_req_inv)
            {
                g_ack_req_inv -= 8;
            }
            g_ack_req_inv = MAX(g_ack_req_inv, 8);
            g_ack_req_inv = MIN(g_ack_req_inv, 2048);

            g_total_send += DATA_PACKET_SIZE;
            if (g_total_send > TOTAL_TRANSMIT_DATA && TOTAL_TRANSMIT_DATA != -1)
                break;
            msgs_completed_send = 0;
            time_taken -= g_time_require;
        }

        if (msgs_completed_send == 0)
        {
            do
            {
                msgs_completed_send = ibv_exp_poll_cq(cq_send, 1, &wc_exp_send, sizeof(struct ibv_exp_wc));
            } while (msgs_completed_send == 0);
            if (msgs_completed_send > 0)
            {
                wr_id = wc_exp_send.wr_id;
                if (ack_tag >= g_ack_req_inv - 1)
                {
                    if ((ack_queue_tail + 1) % ACK_QUEUE_LENGTH != ack_queue_head)
                    {
                        ack_queue[ack_queue_tail].seq = g_send_seq;
                        ack_queue[ack_queue_tail].ack_time_app = send_time;
                        ack_queue[ack_queue_tail].ack_time_hw = ibv_exp_cqe_ts_to_ns(&values.clock_info, wc_exp_send.timestamp);
                        ack_queue_tail = (ack_queue_tail + 1) % ACK_QUEUE_LENGTH;
                    }
                    else if ((ack_queue_tail + 1) % ACK_QUEUE_LENGTH == ack_queue_head)
                    {
                        printf("ERROR: ACK queue is full!! \n");
                        exit(1);
                    }
                    create_data_packet(buf_send + wr_id * ENTRY_SIZE, true);
                    
                    ack_tag = 0;
                }
                else
                {
                    create_data_packet(buf_send + wr_id * ENTRY_SIZE, false);
                    ack_tag++;
                }
                create_send_work_request(wr_send + wr_id, sg_entry_send + wr_id, mr_send, buf_send + wr_id * ENTRY_SIZE, wr_id, DATA);
            }
        }
    }
    pthread_mutex_unlock(&mutex_sender_thread);

    printf("END!!!\n");
}

void *recv_thread_fucntion(void *thread_arg)
{
    struct Thread_arg *args = (struct Thread_arg *)thread_arg;
    int thread_id = args->thread_id;
    int thread_action = args->thread_action;

    unsigned long mask = 8;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }

    struct ibv_exp_values values = {0};
    ibv_exp_query_values(context, IBV_EXP_VALUES_CLOCK_INFO, &values);
    int ret;
    /* 1. Create Complition Queue (CQ) */

    struct ibv_cq *cq_send;
    struct ibv_cq *cq_recv;

    struct ibv_exp_cq_init_attr cq_init_attr;
    memset(&cq_init_attr, 0, sizeof(cq_init_attr));
    cq_init_attr.flags = IBV_EXP_CQ_TIMESTAMP;
    cq_init_attr.comp_mask = IBV_EXP_CQ_INIT_ATTR_FLAGS;
    cq_recv = ibv_exp_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0, &cq_init_attr);
    cq_send = ibv_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0);
    //cq_recv = ibv_create_cq(context, RQ_NUM_DESC, NULL, NULL, 0);
    if (!cq_send || !cq_recv)
    {
        fprintf(stderr, "Couldn't create CQ %d\n", errno);
        exit(1);
    }

    /* 2. Initialize QP */
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_context = NULL,
        /* report send completion to cq */
        .send_cq = cq_send,
        .recv_cq = cq_recv,
        .cap = {
            /* number of allowed outstanding sends without waiting for a completion */
            .max_send_wr = SQ_NUM_DESC,
            .max_recv_wr = RQ_NUM_DESC,
            /* maximum number of pointers in each descriptor */
            .max_send_sge = 1,
            .max_recv_sge = 1,
        },
        .qp_type = IBV_QPT_RAW_PACKET,
    };

    /* 3. Create Queue Pair (QP) - Work request Ring */
    qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp)
    {
        fprintf(stderr, "Couldn't create RSS QP\n");
        exit(1);
    }

    /* 4. Initialize the QP (receive ring) and assign a port */
    struct ibv_qp_attr qp_attr;
    int qp_flags;
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_flags = IBV_QP_STATE | IBV_QP_PORT;
    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.port_num = 1;
    ret = ibv_modify_qp(qp, &qp_attr, qp_flags);
    if (ret < 0)
    {
        fprintf(stderr, "failed modify qp to init\n");
        exit(1);
    }

    memset(&qp_attr, 0, sizeof(qp_attr));

    /* 5. Move the ring to ready to send in two steps (a,b) */
    /* a. Move ring state to ready to receive, this is needed to be able to move ring to ready to send even if receive queue is not enabled */
    qp_flags = IBV_QP_STATE;
    qp_attr.qp_state = IBV_QPS_RTR;
    ret = ibv_modify_qp(qp, &qp_attr, qp_flags);
    if (ret < 0)
    {
        fprintf(stderr, "failed modify qp to receive\n");
        exit(1);
    }

    /* b. Move the ring to ready to send */
    qp_flags = IBV_QP_STATE;
    qp_attr.qp_state = IBV_QPS_RTS;
    ret = ibv_modify_qp(qp, &qp_attr, qp_flags);
    if (ret < 0)
    {
        fprintf(stderr, "failed modify qp to receive\n");
        exit(1);
    }

    /* 9. Allocate Memory for send packet */
    void *buf_send; //sending buffer address
    void *buf_recv; //recving buffer address
    buf_send = malloc(buf_size_send);
    buf_recv = malloc(buf_size_recv);
    if (!buf_send || !buf_recv)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr_send;
    struct ibv_mr *mr_recv;
    mr_send = ibv_reg_mr(pd, buf_send, buf_size_send, IBV_ACCESS_LOCAL_WRITE);
    mr_recv = ibv_reg_mr(pd, buf_recv, buf_size_recv, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_send || !mr_recv)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    //Work request(WR)
    struct ibv_sge sg_entry_send[SQ_NUM_DESC];
    struct ibv_sge sg_entry_recv[RQ_NUM_DESC];
    struct ibv_send_wr wr_send[SQ_NUM_DESC], *bad_wr_send;
    struct ibv_recv_wr wr_recv[RQ_NUM_DESC], *bad_wr_recv;
    struct ibv_wc wc_recv;
    struct ibv_exp_wc wc_exp_recv;
    struct raw_eth_flow_attr flow_attr_pause_recv;
    struct raw_eth_flow_attr
    {
        struct ibv_flow_attr attr;
        struct ibv_flow_spec_eth spec_eth;
    } __attribute__((packed)) flow_attr = {
        .attr = {
            .comp_mask = 0,
            .type = IBV_FLOW_ATTR_NORMAL,
            .size = sizeof(flow_attr),
            .priority = 0,
            .num_of_specs = 1,
            .port = PORT_NUM,
            .flags = 0,
        },
        .spec_eth = {.type = IBV_EXP_FLOW_SPEC_ETH, .size = sizeof(struct ibv_flow_spec_eth), .val = {
                                                                                                  .dst_mac[0] = g_src_mac_addr[0],
                                                                                                  .dst_mac[1] = g_src_mac_addr[1],
                                                                                                  .dst_mac[2] = g_src_mac_addr[2],
                                                                                                  .dst_mac[3] = g_src_mac_addr[3],
                                                                                                  .dst_mac[4] = g_src_mac_addr[4],
                                                                                                  .dst_mac[5] = g_src_mac_addr[5],
                                                                                                  .src_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                                                                                  .ether_type = 0,
                                                                                                  .vlan_tag = 0,
                                                                                              },
                     .mask = {
                         .dst_mac = {BRD_MAC},
                         .src_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                         .ether_type = 0,
                         .vlan_tag = 0,
                     }},
    };

    /* 13. Create steering rule */
    struct ibv_flow *eth_flow;
    eth_flow = ibv_create_flow(qp, &flow_attr.attr);
    if (!eth_flow)
    {
        fprintf(stderr, "Couldn't attach steering flow\n");
        exit(1);
    }

    for (int n = 0; n < RQ_NUM_DESC; n++)
    {
        wr_recv[n].num_sge = 1;
        wr_recv[n].sg_list = &sg_entry_recv[n];
        wr_recv[n].next = NULL;
        /* pointer to packet buffer size and memory key of each packet buffer */
        sg_entry_recv[n].length = ENTRY_SIZE;
        sg_entry_recv[n].lkey = mr_recv->lkey;
        /* each descriptor points to max MTU size buffer */
        sg_entry_recv[n].addr = (uint64_t)buf_recv + ENTRY_SIZE * n;

        /* index of descriptor returned when packet arrives */
        wr_recv[n].wr_id = n;

        ibv_post_recv(qp, &wr_recv[n], &bad_wr_recv);
    }

    uint64_t wr_id = 0;
    int msgs_completed_send = 0;
    int msgs_completed_recv;

    double time_diff = 0;

    long time_taken = 0;

    uint32_t time_start;
    uint32_t time_prev = 0;
    uint32_t prev_seq = 0;
    double rate_curr, rate_prev = 1;
    uint32_t seq;
    int cnt_decrease = 1;
    long ack_time_app;
    uint32_t ack_time_hw;
    long time_now_app;
    uint32_t time_now_hw;
    double rate_arry[5] = {0, 0, 0, 0, 0};
    int arry_p = 0;
    //RECV procedure Loop
    printf("\n RECV Thread %d Loop Started\n", thread_id);
    FILE *fp = fopen("trace_rtt.out", "w");
    fprintf(fp, "rate_median,rate,rate_send,rtt\n");

    double running_time;
    double start_time = 0;
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);

    start_time = (double)time.tv_sec + (double)time.tv_nsec / (1000 * 1000 * 1000);
    while (1)
    {
        /* wait for completion */
        //msgs_completed_recv = ibv_poll_cq(cq_recv, 1, &wc_recv);
        msgs_completed_recv = ibv_exp_poll_cq(cq_recv, 1, &wc_exp_recv, sizeof(struct ibv_exp_wc));
        if (msgs_completed_recv > 0)
        {
            //printf("recv!\n");
            /*
             * completion includes: 
             * -status of descriptor
             * -index of descriptor completing
             * -size of the incoming packets
             */
            g_total_recv += 1;

            struct ethhdr *eth = (struct ethhdr *)((char *)buf_recv + wc_exp_recv.wr_id * ENTRY_SIZE);
            struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
            struct iphdr *ip = (struct iphdr *)(vlan + 1);
            struct lcchdr_ack *lcc = (struct lcchdr_ack *)(ip + 1);
            //If ack request is tagged
            if (lcc->ack == 1)
            {
                time_now_app = g_time;
                if (time_prev == 0)
                {
                    time_prev = lcc->ack_time;
                    goto dequeue;
                }

                time_start = lcc->ack_time;
                time_now_hw = ibv_exp_cqe_ts_to_ns(&values.clock_info, wc_exp_recv.timestamp);
                if (time_start >= time_prev)
                    time_taken = time_start - time_prev;
                else
                    time_taken = time_start + 1 * 1e9 - time_prev;

                time_prev = time_start;
                //printf("================================\n");

                rate_curr = (double)8.0 * DATA_PACKET_SIZE * (lcc->seq - prev_seq) / time_taken;
                rate_arry[arry_p] = rate_curr;
                arry_p = (arry_p + 1) % 3;
                g_recv_rate = find_median(rate_arry, arry_p); //rate_curr * 0.7 + g_recv_rate * 0.3;
                //if (g_recv_rate == 0)
                //    g_recv_rate = rate_curr;
                //printf("%f: %f, %f, %f\n",g_recv_rate, rate_arry[0], rate_arry[1], rate_arry[2]);

                if (g_lcc_mode)
                {
                    if (lcc->seq == 0 || g_recv_rate + 0.15 > g_send_rate)
                    {
                        g_send_rate += 0.05; // + g_send_rate / 10 * 0.02;
                        //printf("increase! %f\n",g_send_rate);
                        cnt_decrease = 1;
                    }
                    else
                    {
                        g_send_rate = g_recv_rate * 0.85; // * (1 - cnt_decrease * 0.1);
                        cnt_decrease++;
                        cnt_decrease = MIN(cnt_decrease, 10);
                        //printf("decrease! %f\n",g_send_rate);
                    }
                    g_time_require = (double)DATA_PACKET_SIZE * 8.0 / (g_send_rate / NUM_SEND_THREAD);
                }
            //printf("timestamp: %lu\n", wc_exp_recv.timestamp);
            //if (prev_seq + g_ack_req_inv != lcc->seq)
            //    printf("Drop detected!!\n");
            dequeue:
                prev_seq = lcc->seq;

                if (ack_queue_head != ack_queue_tail)
                {
                    seq = ack_queue[ack_queue_head].seq;
                    ack_time_app = ack_queue[ack_queue_head].ack_time_app;
                    ack_time_hw = ack_queue[ack_queue_head].ack_time_hw;
                    ack_queue_head = (ack_queue_head + 1) % ACK_QUEUE_LENGTH;

                    if (time_now_app >= ack_time_app)
                        g_rtt_app = time_now_app - ack_time_app;
                    else
                        g_rtt_app = time_now_app + 1 * 1e9 - ack_time_app;

                    if (time_now_hw >= ack_time_hw)
                        g_rtt_hw = time_now_hw - ack_time_hw;
                    else
                        g_rtt_hw = time_now_hw + 1 * 1e9 - ack_time_hw;


                    //printf("\nrecv seq: %d \n", lcc->seq);
                    if (lcc->seq != seq)
                    {
                        //printf("Drop detected!\nSEQ: %d\nNext SEQ: %d\nACK_INV: %d\n\n", lcc->seq, seq, g_ack_req_inv);
                        //for (int i = ack_queue_head; i <= ack_queue_tail; i++)
                       // {
                       //     printf("SEQ: %d\n", ack_queue[i].seq);
                       // }
                       // exit(1);
                        //printf("\n\n\n");
                    }
                }
                else
                {
                    printf("Ack buffer full!!\n");
                }
                //clock_gettime(CLOCK_MONOTONIC, &time);
                //running_time = (double)time.tv_sec + (double)time.tv_nsec / (1000 * 1000 * 1000) - start_time;
                //find_median(rate_array, arry_p);
                //fprintf(fp, "%ld, %ld, %ld\n", lcc->seq, g_rtt_app, g_rtt_hw);
                //fflush(fp);
            }

            ibv_post_recv(qp, &wr_recv[wc_recv.wr_id], &bad_wr_recv);
        }
        else if (msgs_completed_recv < 0)
        {
            printf("Polling error\n");
            exit(1);
        }
    }
    printf("END!!!\n");
}

double find_median(double *rate_array, int arry_p)
{
    double array_tmp[3];
    memcpy(array_tmp, rate_array, sizeof(double) * 3);

    if (rate_array[1] == 0)
    {
        return rate_array[0];
    }
    else if (rate_array[2] == 0)
    {
        return MIN(rate_array[0], rate_array[1]);
    }
    else if (rate_array[3] == 0)
    {
        quicksort(0, 2, array_tmp);
        return array_tmp[1];
    }
    else if (rate_array[4] == 0)
    {
        quicksort(0, 3, array_tmp);
        return array_tmp[2];
    }
    quicksort(0, 4, array_tmp);
    return array_tmp[2];

    /*int before = (arry_p - 1) % 10;
    int before2 = (arry_p - 2) % 10;
    if(before < 0 )
        before += 10;
    if(before2 < 0 )
        before2 += 10;

    if (rate_array[arry_p] >= rate_array[before])
    {
        if (rate_array[before] >= rate_array[before2])
        {
            return rate_array[before];
        }
        else if (rate_array[arry_p] >= rate_array[before2])
        {
            return rate_array[before2];
        }
        else
        {
            return rate_array[arry_p];
        }
    }
    else if (rate_array[before] >= rate_array[arry_p])
    {
        if (rate_array[arry_p] >= rate_array[before2])
        {
            return rate_array[arry_p];
        }
        else if (rate_array[before] >= rate_array[before2])
        {
            return rate_array[before2];
        }
        else
        {
            return rate_array[before];
        }
    }*/
}

void quicksort(int left, int right, double *arr)
{

    if (arr[right] == 0)
    {
        quicksort(left, right - 1, arr);
        return;
    }
    int i = left, j = right;
    double pivot = arr[(left + right) / 2];
    double temp;
    do
    {
        while (arr[i] < pivot)
            i++;
        while (arr[j] > pivot)
            j--;
        if (i <= j)
        {
            temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
            i++;
            j--;
        }
    } while (i <= j);

    /* recursion */
    if (left < j)
        quicksort(left, j, arr);

    if (i < right)
        quicksort(i, right, arr);
}

void swap(double *a, double *b)
{
    double t = *a;
    *a = *b;
    *b = t;
}

int main()
{
    printf("\n\n %d", -1 % 5);
    unsigned long mask = 1;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }

    char readBuff[512];
    char varBuff[256];

    FILE *fp;

    memset(varBuff, 0, 256);
    printf("\n Readming Conf file...\n\n");
    fp = fopen("lcc.conf", "r");
    if (fp)
    {
        while (!feof(fp))
        {
            memset(readBuff, 0, 512);

            if (fgets(readBuff, 512, fp) == NULL)
            {
                continue;
            }
            if (strncasecmp(readBuff, "#", strlen("#")) == 0)
            {
                continue;
            }
            if (strncasecmp(readBuff, "VLAN_ID", strlen("VLAN_ID")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hd", &g_vlan_id);
                printf(" VLAN_ID : %d", g_vlan_id);
                g_vlan_hdr = g_vlan_id + (3 << 13);
            }
            if (strncasecmp(readBuff, "SRC_MAC", strlen("SRC_MAC")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
                       &g_src_mac_addr[0], &g_src_mac_addr[1], &g_src_mac_addr[2],
                       &g_src_mac_addr[3], &g_src_mac_addr[4], &g_src_mac_addr[5]);
                printf(" SRC_MAC : %s", varBuff);
            }
            if (strncasecmp(readBuff, "DST_MAC", strlen("DST_MAC")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
                       &g_dst_mac_addr[0], &g_dst_mac_addr[1], &g_dst_mac_addr[2],
                       &g_dst_mac_addr[3], &g_dst_mac_addr[4], &g_dst_mac_addr[5]);
                printf(" DST_MAC : %s", varBuff);
            }
            if (strncasecmp(readBuff, "SRC_IP", strlen("SRC_IP")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhd.%hhd.%hhd.%hhd",
                       &g_src_ip[0], &g_src_ip[1], &g_src_ip[2], &g_src_ip[3]);
                printf(" SRC_IP : %s", varBuff);
            }
            if (strncasecmp(readBuff, "DST_IP", strlen("DST_IP")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhd.%hhd.%hhd.%hhd",
                       &g_dst_ip[0], &g_dst_ip[1], &g_dst_ip[2], &g_dst_ip[3]);
                printf(" DST_IP : %s", varBuff);
            }
            if (strncasecmp(readBuff, "INIT_RATE", strlen("INIT_RATE")) == 0)
            {
                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%lf", &g_init_rate);
                printf("\n INIT_RATE : %f", g_init_rate);
            }
            if (strncasecmp(readBuff, "LCC_MODE", strlen("LCC_MODE")) == 0)
            {
                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                if (strncasecmp(varBuff, "ON", strlen("ON")) == 0)
                    g_lcc_mode = true;
                else if (strncasecmp(varBuff, "OFF", strlen("OFF")) == 0)
                    g_lcc_mode = false;
                printf("\n LCC_MODE : %d", g_lcc_mode);
            }
        }
    }
    printf("\n\n Read End...\n\n");

    fclose(fp);

    /*1. Get the list of offload capable devices */
    dev_list = ibv_get_device_list(NULL);
    if (!dev_list)
    {
        perror("Failed to get devices list");
        exit(1);
    }

    /* In this example, we will use the first adapter (device) we find on the list (dev_list[0]) . You may change the code in case you have a setup with more than one adapter installed. */
    ib_dev = dev_list[0];
    if (!ib_dev)
    {
        fprintf(stderr, "IB device not found\n");
        exit(1);
    }

    /* 2. Get the device context */
    /* Get context to device. The context is a descriptor and needed for resource tracking and operations */
    context = ibv_open_device(ib_dev);
    if (!context)
    {
        fprintf(stderr, "Couldn't get context for %s\n",
                ibv_get_device_name(ib_dev));
        exit(1);
    }

    struct ibv_exp_device_attr attr;

    ibv_exp_query_device(context, &attr);
    if (attr.comp_mask & IBV_EXP_DEVICE_ATTR_WITH_TIMESTAMP_MASK)
    {
        if (attr.timestamp_mask)
        {
            printf("timestampe is enabled!\n");
        }
    }
    if (attr.comp_mask & IBV_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK)
    {
        if (attr.hca_core_clock)
        {
            /* reporting the device's clock is supported. */
            /* attr.hca_core_clock is the frequency in MHZ */
        }
    }

    /* 3. Allocate Protection Domain */
    /* Allocate a protection domain to group memory regions (MR) and rings */
    pd = ibv_alloc_pd(context);
    if (!pd)
    {
        fprintf(stderr, "Couldn't allocate PD\n");
        exit(1);
    }

    pthread_t clock_tread;
    pthread_create(&clock_tread, NULL, clock_thread_function, NULL);

    pthread_t recv_tread;
    struct Thread_arg recv_thread_arg;
    recv_thread_arg.thread_id = 0;
    recv_thread_arg.thread_action = RECEIVING_ONLY;
    pthread_create(&recv_tread, NULL, recv_thread_fucntion, &recv_thread_arg);

    usleep(100000);

    pthread_t p_thread[NUM_SEND_THREAD];
    int thread_id[NUM_SEND_THREAD];
    struct Thread_arg *thread_arg = (struct Thread_arg *)malloc(sizeof(struct Thread_arg) * NUM_SEND_THREAD);

    for (int i = 0; i < NUM_SEND_THREAD; i++)
    {
        thread_arg[i].thread_id = i;
        thread_arg[i].thread_action = SENDING_AND_RECEVING;
        pthread_create(&p_thread[i], NULL, send_thread_fucntion, (void *)(thread_arg + i));
    }

    fp = fopen("trace.out", "w");
    fprintf(fp, "time, recv_rate, send_rate, rtt_app, rtt_hw, ack_queue_len\n");
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    double start_time = (double)time.tv_sec + (double)time.tv_nsec / (1000 * 1000 * 1000);
    double time_now;
    int sleep_cnt = 0;
    struct timeval val;
    struct tm *ptm;
    while (1)
    {
        usleep(10);
        gettimeofday(&val, NULL);
        ptm = localtime(&val.tv_sec);

        if (g_recv_rate > 0)
            fprintf(fp, "%02d%02d%02d.%06ld, %f, %f, %ld, %ld ,%d\n", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, val.tv_usec, g_recv_rate, g_send_rate, g_rtt_app, g_rtt_hw ,ack_queue_tail - ack_queue_head);
        sleep_cnt++;
        if (sleep_cnt > 10000)
        {
            printf("%02d%02d%02d.%06ld, %f, %f, %ld, %ld, %d, %d\n", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, val.tv_usec, g_recv_rate, g_send_rate, g_rtt_app, g_rtt_hw ,ack_queue_tail - ack_queue_head, g_ack_req_inv);
            sleep_cnt = 0;
        }
    }

    fclose(fp);

    printf("We are done \n");

    return 0;
}
