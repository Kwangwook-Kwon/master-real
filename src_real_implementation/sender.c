#define _GNU_SOURCE
#include <infiniband/verbs.h>
#include <infiniband/verbs_exp.h>
#include <stdio.h>
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

void create_data_packet(void *buf)
{
    // Ether header
    struct ethhdr *eth = (struct ethhdr *)buf;
    memcpy(eth->h_dest, g_dst_mac_addr, ETH_ALEN);
    memcpy(eth->h_source, g_src_mac_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_8021Q);

    //VLAN header
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    memcpy(&vlan->h_vlan_TCI, g_vlan_hdr, 2);
    vlan->h_vlan_encapsulated_proto = htons(ETH_P_IP);

    //IP header
    struct iphdr *ip = (struct iphdr *)(vlan + 1);
    size_t ip_len = DATA_PACKET_SIZE - sizeof(struct ethhdr) - sizeof(struct vlan_hdr);
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 64;
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
    size_t lcc_len = ip_len - sizeof(struct ip
    hdr);
    lcc->source = UDP_SRC;
    lcc->dest = UDP_DST;
    lcc->len = htons((uint16_t)lcc_len);
    lcc->check = 0; //Zero means no checksum check at revciever
    lcc->data = 1;
    lcc->seq = g_send_seq;
    if (g_send_seq % ACK_REQ_INTERVAL == 0)
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

    unsigned long mask = 128;
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
    unsigned long mask = 512 * (thread_id + 1);
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }

    int ret;
    /* 1. Create Complition Queue (CQ) */
    struct ibv_cq *cq_send;
    struct ibv_cq *cq_recv;
    cq_send = ibv_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0);
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
                                                                                                  .dst_mac = {SRC_MAC},
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

    create_recv_work_request(qp, &wr_recv, &sg_entry_recv, mr_recv, buf_recv, &flow_attr_pause_recv);

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
    g_time_require = (double)DATA_PACKET_SIZE * 8.0 / (SENDING_RATE_IN_GIGA / NUM_SEND_THREAD);
    g_prev_rate = SENDING_RATE_IN_GIGA;
    g_send_rate = SENDING_RATE_IN_GIGA;

    time_prev = g_time;

    //Sending procedure Loop
    printf("\n SEND Thread %d Loop Started\n", thread_id);
    printf("\ntime require: %ld\n", g_time_require);
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
            if ((g_send_seq - 1) % ACK_REQ_INTERVAL == 0 && (ack_queue_tail + 1) % ACK_QUEUE_LENGTH != ack_queue_head)
            {
                ack_queue[ack_queue_tail].seq = g_send_seq - 1;
                ack_queue[ack_queue_tail].ack_time = g_time;
                ack_queue_tail = (ack_queue_tail + 1) % ACK_QUEUE_LENGTH;
            }
            else if ((ack_queue_tail + 1) % ACK_QUEUE_LENGTH == ack_queue_head)
            {

                printf("ERROR: ACK queue is full!!\n");
                exit(1);
            }

            if (ret < 0)
            {
                fprintf(stderr, "failed in post send\n");
                exit(1);
            }
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
                msgs_completed_send = ibv_poll_cq(cq_send, 1, &wc);
            } while (msgs_completed_send == 0);
            if (msgs_completed_send > 0)
            {
                wr_id = wc.wr_id;
                //printf("wrid: %d\n ",wr_id);
                create_data_packet(buf_send + wr_id * ENTRY_SIZE);
                create_send_work_request(wr_send + wr_id, sg_entry_send + wr_id, mr_send, buf_send + wr_id * ENTRY_SIZE, wr_id, DATA);
            }
        }
    }
    printf("END!!!\n");
}

void *recv_thread_fucntion(void *thread_arg)
{
    struct Thread_arg *args = (struct Thread_arg *)thread_arg;
    int thread_id = args->thread_id;
    int thread_action = args->thread_action;

    unsigned long mask = 2048 * (thread_id + 1);
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
                                                                                                  .dst_mac = {SRC_MAC},
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
    long time_require = (double)DATA_PACKET_SIZE * 8.0 / (SENDING_RATE_IN_GIGA / NUM_SEND_THREAD);

    long time_taken = 0;

    uint32_t time_start;
    uint32_t time_prev = 0;
    uint32_t prev_seq = 0;
    double rate_curr, rate_prev = 1;
    uint32_t seq;
    long ack_time;
    //RECV procedure Loop
    //printf("\n RECV Thread %d Loop Started\n", thread_id);
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
            g_total_recv += wc_recv.byte_len;

            struct ethhdr *eth = (struct ethhdr *)((char *)buf_recv + wc_exp_recv.wr_id * ENTRY_SIZE);
            struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
            struct iphdr *ip = (struct iphdr *)(vlan + 1);
            struct lcchdr_ack *lcc = (struct lcchdr_ack *)(ip + 1);

            //If ack request is tagged
            if (lcc->ack == 1)
            {
                time_start = lcc->ack_time;
                //time_start = ibv_exp_cqe_ts_to_ns(&values.clock_info, wc_exp_recv.timestamp);
                if (time_start >= time_prev)
                    time_taken = time_start - time_prev;
                else
                    time_taken = time_start + 1 * 1e9 - time_prev;
                //printf("================================\n");

                rate_curr = (double)8.0 * DATA_PACKET_SIZE * ACK_REQ_INTERVAL / time_taken;
                rate_prev = g_recv_rate;
                g_recv_rate = rate_curr;

                if (lcc->seq == 0 || rate_curr > g_prev_rate)
                {
                    g_prev_rate = g_send_rate;
                    g_send_rate +=  0.1;
                    //printf("increase! %f\n",g_send_rate);
                }
                else
                {
                    g_prev_rate = 0;
                    g_send_rate = g_send_rate * 0.95;
                    //printf("decrease! %f\n",g_send_rate);
                }
                g_time_require = (double)DATA_PACKET_SIZE * 8.0 / (g_send_rate / NUM_SEND_THREAD);

                time_prev = time_start;
                //printf("timestamp: %lu\n", wc_exp_recv.timestamp);
                if (prev_seq + ACK_REQ_INTERVAL != lcc->seq)
                    printf("Drop detected!!\n");
                prev_seq = lcc->seq;

                if (ack_queue_head != ack_queue_tail)
                {
                    seq = ack_queue[ack_queue_head].seq;
                    ack_time = ack_queue[ack_queue_head].ack_time;
                    ack_queue_head = (ack_queue_head + 1) % ACK_QUEUE_LENGTH;

                    if (lcc->seq != seq)
                    {
                        printf("Drop detected!\nSEQ: %d\nNext SEQ: %d\n", lcc->seq, seq);
                        exit(1);
                    }
                }
                else
                {
                    printf("Ack buffer full!!\n");
                }
            }

            ibv_post_recv(qp, &wr_recv[wc_exp_recv.wr_id], &bad_wr_recv);
        }
        else if (msgs_completed_recv < 0)
        {
            printf("Polling error\n");
            exit(1);
        }
    }
    printf("END!!!\n");
}

int main()
{
    unsigned long mask = 256;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }
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

    usleep(1000);

    pthread_t p_thread[NUM_SEND_THREAD];
    int thread_id[NUM_SEND_THREAD];
    struct Thread_arg *thread_arg = (struct Thread_arg *)malloc(sizeof(struct Thread_arg) * NUM_SEND_THREAD);

    for (int i = 0; i < NUM_SEND_THREAD; i++)
    {
        thread_arg[i].thread_id = i;
        thread_arg[i].thread_action = SENDING_AND_RECEVING;
        pthread_create(&p_thread[i], NULL, send_thread_fucntion, (void *)(thread_arg + i));
    }

    while (1)
    {
        usleep(50000);
        printf("recv_rate: %f\n", g_recv_rate);
    }

    printf("We are done\n");

    return 0;
}
