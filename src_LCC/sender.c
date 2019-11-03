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
#include <stdio.h>
#include "ranvar.h"
#include "ranvar.cc"

void create_ack_packet(void *buf, uint32_t seq, uint32_t ack_time, uint8_t *client_ip)
{

    // Ether header
    struct ethhdr *eth = (struct ethhdr *)buf;
    memcpy(eth->h_dest, g_dst_mac_addr, ETH_ALEN);
    memcpy(eth->h_source, g_src_mac_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_8021Q);

    //VLAN header
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    vlan->h_vlan_TCI = htons(g_vlan_hdr_ack);
    vlan->h_vlan_encapsulated_proto = htons(ETH_P_IP);

    //IP header
    struct iphdr *ip = (struct iphdr *)(vlan + 1);
    size_t ip_len = ACK_PACKET_SIZE - sizeof(struct ethhdr) - sizeof(struct vlan_hdr);
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 64;
    ip->tot_len = htons((uint16_t)ip_len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    memcpy(&ip->saddr, g_recv_ip, 4);
    memcpy(&ip->daddr, client_ip, 4);
    ip->check = gen_ip_checksum((char *)ip, sizeof(struct iphdr));

    //LCC Header
    struct lcchdr_ack *lcc = (struct lcchdr_ack *)(ip + 1);
    memset(lcc, 0, sizeof(struct lcchdr_ack));
    size_t lcc_len = ip_len - sizeof(struct iphdr);
    lcc->source = UDP_SRC;
    if (g_cc_mode == STREAM)
        lcc->dest = UDP_DST;
    else
        lcc->dest = UDP_DST;
    lcc->len = htons((uint16_t)lcc_len);
    lcc->check = 0; //Zero means no checksum check at revciever
    lcc->ack = 1;
    lcc->seq = seq;
    lcc->ack_time = ack_time;
    //g_send_seq++;
    //if (g_send_seq % 8 == 0)
    //    lcc->ackReq = 1;

    // Payload : Data150
    //void *payload = lcc + 1;
    //char D = 'D';
    //memset(payload, D, lcc_len - sizeof(struct lcchdr));
}

void create_data_packet(void *buf, bool ack)
{
    // Ether header
    struct ethhdr *eth = (struct ethhdr *)buf;
    memcpy(eth->h_dest, g_dst_mac_addr, ETH_ALEN);
    memcpy(eth->h_source, g_src_mac_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_8021Q);

    //VLAN header
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    vlan->h_vlan_TCI = htons(g_vlan_hdr_data);
    vlan->h_vlan_encapsulated_proto = htons(ETH_P_IP);

    //IP header
    struct iphdr *ip = (struct iphdr *)(vlan + 1);
    size_t ip_len;
    if (g_flow_mode == INFINITE)
        ip_len = DATA_PACKET_SIZE - sizeof(struct ethhdr) - sizeof(struct vlan_hdr);
    else
        ip_len = MIN(DATA_PACKET_SIZE - sizeof(struct ethhdr) - sizeof(struct vlan_hdr), sizeof(struct iphdr) + sizeof(struct lcchdr) + g_flow_rem);
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
    if (ack == true || lcc->seq == 0)
        lcc->ackReq = 1;
    g_send_seq++;

    // Payload : Data150
    void *payload = lcc + 1;
    char D = 'D';
    memset(payload, D, lcc_len - sizeof(struct lcchdr));

    if (g_flow_mode != INFINITE)
        g_flow_rem -= lcc_len - sizeof(struct lcchdr);
    if (g_flow_rem <= 0)
    {
        lcc->endofdata = 1;
        lcc->ackReq = 1;
    }
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
    struct ethhdr *eth = (struct ethhdr *)((char *)buf);
    struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
    struct iphdr *ip = (struct iphdr *)(vlan + 1);
    /* scatter/gather entry describes location and size of data to send*/
    sg_entry->addr = (uint64_t)buf;
    if (packet_type == DATA)
        sg_entry->length = sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + ntohs(ip->tot_len);
    else if (packet_type == ACK)
        sg_entry->length = ACK_PACKET_SIZE;
    else if (packet_type == DUMMY)
        sg_entry->length = 60;
    sg_entry->lkey = mr->lkey;
    memset(wr, 0, sizeof(struct ibv_send_wr));

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
    sg_entry->length = ENTRY_SIZE;
    sg_entry->lkey = mr->lkey;

    wr->num_sge = 1;
    wr->sg_list = sg_entry;
    wr->next = NULL;
    for (int n = 0; n < RQ_NUM_DESC; n++)
    {
        sg_entry->addr = (uint64_t)buf + ENTRY_SIZE * n;
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

    unsigned long mask = 32 * g_process;
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

void *send_packet(void *thread_arg)
{
    unsigned long mask = 8 * g_process;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }

    int ret;
    /* 1. Create Complition Queue (CQ) */

    struct ibv_exp_values values = {0};
    ibv_exp_query_values(context, IBV_EXP_VALUES_CLOCK_INFO, &values);

    struct ibv_cq *cq_send;
    //struct ibv_cq *cq_recv;
    struct ibv_exp_cq_init_attr cq_init_attr;

    memset(&cq_init_attr, 0, sizeof(cq_init_attr));
    cq_init_attr.flags = IBV_EXP_CQ_TIMESTAMP;
    cq_init_attr.comp_mask = IBV_EXP_CQ_INIT_ATTR_FLAGS;
    cq_send = ibv_exp_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0, &cq_init_attr);
    //cq_recv = ibv_create_cq(context, RQ_NUM_DESC, NULL, NULL, 0);
    if (!cq_send) //|| !cq_recv)
    {
        fprintf(stderr, "Couldn't create CQ send %d\n", errno);
        exit(1);
    }

    /* 2. Initialize QP */
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_context = NULL,
        /* report send completion to cq */
        .send_cq = cq_send,
        .recv_cq = cq_send,
        .cap = {
            /* number of allowed outstanding sends without waiting for a completion */
            .max_send_wr = SQ_NUM_DESC,
            .max_recv_wr = 0,
            /* maximum number of pointers in each descriptor */
            .max_send_sge = 1,
            //.max_recv_sge = 1,
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
    //void *buf_send; //sending buffer address
    //void *buf_recv; //recving buffer address
    //g_buf_send = malloc(buf_size_send);
    buf_send = malloc(buf_size_send);
    //buf_recv = malloc(buf_size_recv);
    if (!buf_send)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr_send;
    mr_send = ibv_reg_mr(pd, buf_send, buf_size_send, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_send) // || !mr_recv)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    //Work request(WR)
    struct ibv_sge sg_entry_send[SQ_NUM_DESC];
    struct ibv_send_wr wr_send[SQ_NUM_DESC], *bad_wr_send;
    struct ibv_exp_wc wc_exp_send[SQ_NUM_DESC];

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
    int wr_id_i = 0;
    int msgs_completed_send = 0;
    void *buf;
    long send_time;
    bool loop = true;
    bool endof_data;

    msgs_completed_send = ibv_exp_poll_cq(cq_send, SQ_NUM_DESC, wc_exp_send, sizeof(struct ibv_exp_wc));
    if (msgs_completed_send > 0)
    {
        for (int i = 0; i < msgs_completed_send; i++)
        {
            if ((data_allow_queue_tail + 1) % DATA_QUEUE_LENGTH != data_allow_queue_head)
            {
                data_allow_queue[data_allow_queue_tail].wr_id = wc_exp_send[i].wr_id;
                data_allow_queue_tail = (data_allow_queue_tail + 1) % DATA_QUEUE_LENGTH;
            }
            else
            {
                fprintf(stderr, "Data allow queue is full \n");
                exit(1);
            }
        }
    }
    bool ack;
    bool endofdata;
    uint32_t seq;
    uint32_t timestamp;

    while (1)
    {
        loop = true;
        if (data_queue_head != data_queue_tail)
        {
            struct ethhdr *eth = (struct ethhdr *)((char *)data_queue[data_queue_head].buf);
            struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
            struct iphdr *ip = (struct iphdr *)(vlan + 1);
            struct lcchdr_ack *lcc = (struct lcchdr_ack *)(ip + 1);
            wr_id = data_queue[data_queue_head].wr_id;
            ack = lcc->ackReq;
            endofdata = lcc->endofdata;
            seq = lcc->seq;

            create_send_work_request(wr_send + wr_id, sg_entry_send + wr_id, mr_send, data_queue[data_queue_head].buf, wr_id, DATA);
            data_queue_head = (data_queue_head + 1) % DATA_QUEUE_LENGTH;
            //printf("seq: %d\n", seq);

            ret = ibv_post_send(qp, wr_send + wr_id, &bad_wr_send);
            send_time = g_time;

            if (ack == 1) // || g_cc_mode == STREAM)
            {
                do
                {
                    msgs_completed_send = ibv_exp_poll_cq(cq_send, SQ_NUM_DESC, wc_exp_send, sizeof(struct ibv_exp_wc));
                    if (msgs_completed_send > 0)
                    {
                        for (int i = 0; i < msgs_completed_send; i++)
                        {
                            if (wc_exp_send[i].wr_id == wr_id)
                            {
                                loop = false;
                                timestamp = ibv_exp_cqe_ts_to_ns(&values.clock_info, wc_exp_send[i].timestamp);
                            }
                            if ((data_allow_queue_tail + 1) % DATA_QUEUE_LENGTH != data_allow_queue_head)
                            {
                                data_allow_queue[data_allow_queue_tail].wr_id = wc_exp_send[i].wr_id;
                                data_allow_queue_tail = (data_allow_queue_tail + 1) % DATA_QUEUE_LENGTH;
                            }
                            else
                            {
                                fprintf(stderr, "Data allow queue is full \n");
                                exit(1);
                            }
                        }
                    }
                } while (msgs_completed_send == 0 || loop);
                if ((sent_queue_tail + 1) % SENT_QUEUE_LENGTH != sent_queue_head && ack == 1)
                {
                    sent_queue[sent_queue_tail].endofdata = endofdata;
                    sent_queue[sent_queue_tail].seq = seq;
                    sent_queue[sent_queue_tail].sent_time_hw = timestamp;
                    sent_queue[sent_queue_tail].sent_time_app = send_time;
                    sent_queue_tail = (sent_queue_tail + 1) % SENT_QUEUE_LENGTH;
                }
                else if ((sent_queue_tail + 1) % SENT_QUEUE_LENGTH == sent_queue_head)
                {
                    fprintf(stderr, "ACK allow queue is full \n");
                    exit(1);
                }
            }

            msgs_completed_send = ibv_exp_poll_cq(cq_send, SQ_NUM_DESC, wc_exp_send, sizeof(struct ibv_exp_wc));
            if (msgs_completed_send > 0)
            {
                for (int i = 0; i < msgs_completed_send; i++)
                {
                    if ((data_allow_queue_tail + 1) % DATA_QUEUE_LENGTH != data_allow_queue_head)
                    {
                        data_allow_queue[data_allow_queue_tail].wr_id = wc_exp_send[i].wr_id;
                        data_allow_queue_tail = (data_allow_queue_tail + 1) % DATA_QUEUE_LENGTH;
                    }
                    else
                    {
                        fprintf(stderr, "Data allow queue is full \n");
                        exit(1);
                    }
                }
            }

            if (ret < 0)
            {
                fprintf(stderr, "failed in post send\n");
                exit(1);
            }
        }
        else
        {
            msgs_completed_send = ibv_exp_poll_cq(cq_send, SQ_NUM_DESC, wc_exp_send, sizeof(struct ibv_exp_wc));
            if (msgs_completed_send > 0)
            {
                for (int i = 0; i < msgs_completed_send; i++)
                {
                    if ((data_allow_queue_tail + 1) % DATA_QUEUE_LENGTH != data_allow_queue_head)
                    {
                        data_allow_queue[data_allow_queue_tail].wr_id = wc_exp_send[i].wr_id;
                        data_allow_queue_tail = (data_allow_queue_tail + 1) % DATA_QUEUE_LENGTH;
                    }
                    else
                    {
                        fprintf(stderr, "Data allow queue is full \n");
                        exit(1);
                    }
                }
            }
        }
    }
}

void *send_data(void *thread_arg)
{
    unsigned long mask = 4 * g_process;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }
    int ret;
    int msgs_completed_send = 0;
    long time_taken = 0;
    long time_start, time_prev;
    double time_diff = 0;
    int ack_tag = g_ack_req_inv - 1;
    int wr_id;
    clock_t flow_start;
    float fct;
    //    uint32_t flow_id = 0;
    uint8_t dst;
    int wait = 0;

    FILE *trace = fopen("trace_flow.out", "w");
    fprintf(trace, "flow_id, flow_size, fct, src, dst\n");
    fflush(trace);

    if (g_cc_mode == LCC || g_cc_mode == STREAM)
    {
        g_time_require = (double)DATA_PACKET_SIZE * 8.0 / (g_init_rate / NUM_SEND_THREAD);
    }

    else if (g_cc_mode == TIMELY)
    {
        g_time_require = (double)DATA_PACKET_SIZE * 8.0 * 16 / (g_init_rate / NUM_SEND_THREAD);
        g_ack_req_inv = 16;
    }

    g_send_rate = g_init_rate;

    time_prev = g_time;

    if (g_flow_mode == DYNAMIC)
    {
        srand((unsigned)time(NULL) + g_seed);
        g_flow_size = get_length();
        g_flow_rem = g_flow_size;
        g_flow_active = true;
        flow_start = clock();
        do
        {
                dst = rand() % 4 + 9;
        } while (dst == g_src_ip[2]);
        g_dst_ip[2] = dst;
    }

    while (1)
    {
        time_start = g_time;
        if (time_start >= time_prev)
            time_taken += MIN((time_start - time_prev), SEND_BUCKET_LIMIT);
        else
            time_taken += MIN((time_start + 1 * 1e9 - time_prev), SEND_BUCKET_LIMIT);
        time_prev = time_start;

        if (time_taken >= g_time_require && data_allow_queue_head != data_allow_queue_tail && (data_queue_tail + 1) % DATA_QUEUE_LENGTH != data_queue_head || g_send_seq < 16)
        {
            if (g_send_seq >= 16)
                time_taken -= g_time_require;
            if (g_cc_mode == LCC || g_cc_mode == STREAM)
            {

                wr_id = data_allow_queue[data_allow_queue_head].wr_id;
                data_allow_queue_head = (data_allow_queue_head + 1) % DATA_QUEUE_LENGTH;

                if (ack_tag >= g_ack_req_inv - 1) // && g_cc_mode == LCC)
                {
                    create_data_packet(buf_send + wr_id * ENTRY_SIZE, true);
                    ack_tag = 0;
                    if (2 * g_rtt_hw > g_time_require * g_ack_req_inv)
                        g_ack_req_inv += 1;
                    else if (3 * g_rtt_hw < g_time_require * g_ack_req_inv)
                    {
                        g_ack_req_inv -= 1;
                    }
                    g_ack_req_inv = MAX(g_ack_req_inv, 8);
                    g_ack_req_inv = MIN(g_ack_req_inv, 32);
                }
                else
                {
                    create_data_packet(buf_send + wr_id * ENTRY_SIZE, false);
                    ack_tag++;
                }

                data_queue[data_queue_tail].buf = buf_send + wr_id * ENTRY_SIZE;
                data_queue[data_queue_tail].wr_id = wr_id;
                data_queue_tail = (data_queue_tail + 1) % DATA_QUEUE_LENGTH;
            }
            else if (g_cc_mode == TIMELY)
            {
                for (int i = 0; i < 16; i++)
                {
                    //pthread_mutex_lock(&mutex_sender_thread);
                    wr_id = data_allow_queue[data_allow_queue_head].wr_id;
                    data_allow_queue_head = (data_allow_queue_head + 1) % DATA_QUEUE_LENGTH;
                    //pthread_mutex_unlock(&mutex_sender_thread);

                    if (i == 15)
                    {
                        create_data_packet(buf_send + wr_id * ENTRY_SIZE, true);
                    }
                    else
                    {
                        create_data_packet(buf_send + wr_id * ENTRY_SIZE, false);
                    }
                    g_total_send += DATA_PACKET_SIZE;
                    if (ret < 0)
                    {
                        fprintf(stderr, "failed in post send\n");
                        exit(1);
                    }

                    data_queue[data_queue_tail].buf = buf_send + wr_id * ENTRY_SIZE;
                    data_queue[data_queue_tail].wr_id = wr_id;
                    data_queue_tail = (data_queue_tail + 1) % DATA_QUEUE_LENGTH;
                    if (g_flow_rem <= 0)
                    {
                        goto outerloop;
                    }
                }
            }
        }
    outerloop:
        if (g_flow_rem <= 0)
        {
            while (g_flow_active == true)
            {
                usleep(1);
                wait++;
                //if (wait > 100000)
                //{
                wait = 0;
                //printf("skipped!!! flowid: %d dest: %d\n", g_flow_id);
                //sent_queue_head = 0;
                //sent_queue_tail = 0;
                //goto skip;
                //}
            }
            fprintf(trace, "%d, %ld, %ld, %d, %d\n", g_flow_id, g_flow_size, g_fct, g_src_ip[2] - 8, g_dst_ip[2] - 8);
            fflush(trace);
            //if(g_cc_mode == STREAM)
            //    usleep((rand()%10)*1000);
        skip:
            pthread_mutex_lock(&mutex_flow_complete_flag);
            g_flow_active = true;
            pthread_mutex_unlock(&mutex_flow_complete_flag);
            g_flow_id++;
            if (g_num_flows < g_flow_id)
            {
                fprintf(stderr, "\n\nALL FLOWS ARE FINNISHED!\n\n");
                exit(1);
            }
            do
            {
                dst = rand() % 4 + 9;
            } while (dst == g_src_ip[2]);
            g_dst_ip[2] = dst;

            g_flow_size = get_length();
            g_flow_rem = g_flow_size;

            if (g_flow_size <= 0)
            {
                printf("invalid g_flow_size\n");
                exit(1);
            }

            if (g_cc_mode == LCC)
                g_ack_req_inv = 8;
            else
                g_ack_req_inv = 16;

            if (g_cc_mode == LCC || g_cc_mode == STREAM)
            {
                g_time_require = (double)DATA_PACKET_SIZE * 8.0 / (g_init_rate / NUM_SEND_THREAD);
            }

            else if (g_cc_mode == TIMELY)
            {
                g_time_require = (double)DATA_PACKET_SIZE * 8.0 * 16 / (g_init_rate / NUM_SEND_THREAD);
                g_ack_req_inv = 16;
            }

            g_send_rate = g_init_rate;

            g_send_seq = 0;
            ack_tag = 0;

            time_taken = 0;
            time_prev = g_time;
        }
    }
    printf("thread finished!\n");
}

void *recv_ack(void *thread_arg)
{
    struct Thread_arg *args = (struct Thread_arg *)thread_arg;
    int thread_id = args->thread_id;
    int thread_action = args->thread_action;

    unsigned long mask = 16 * g_process;
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
    //cq_send = ibv_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0);
    if (!cq_recv)
    {
        fprintf(stderr, "Couldn't create CQ %d\n", errno);
        exit(1);
    }

    /* 2. Initialize QP */
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_context = NULL,
        /* report send completion to cq */
        .send_cq = cq_recv,
        .recv_cq = cq_recv,
        .cap = {
            /* number of allowed outstanding sends without waiting for a completion */
            .max_send_wr = 0,
            .max_recv_wr = RQ_NUM_DESC,
            /* maximum number of pointers in each descriptor */
            //.max_send_sge = 1,
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
    void *buf_recv; //recving buffer address
    buf_recv = malloc(buf_size_recv);
    if (!buf_recv)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr_recv;
    mr_recv = ibv_reg_mr(pd, buf_recv, buf_size_recv, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_recv)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    //Work request(WR)
    struct ibv_sge sg_entry_recv[RQ_NUM_DESC];
    struct ibv_recv_wr wr_recv[RQ_NUM_DESC], *bad_wr_recv;
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

    FILE *fp = fopen("trace_rtt.out", "w");
    fprintf(fp, "time, rate_recv, rate_send, rtt_hw\n");

    uint64_t wr_id = 0;

    int msgs_completed_recv;
    int mN = 0;

    uint8_t client_ip[4];

    uint32_t time_start;
    uint32_t time_prev = 0;
    uint32_t prev_seq = 0;
    uint32_t seq;
    uint32_t time_now_hw;
    uint32_t sent_time_hw;

    double rate_curr;
    double rate_diff;
    double prev_rate_diff = 0;
    double rate_diff_grad = 0;
    double normalized_gradiant;

    long time_taken = 0;
    long sent_time_app;
    long time_now_app;
    long prev_rtt;
    long new_rtt_diff;
    long rtt_diff;

    struct timeval val;
    struct tm *ptm;
    struct ethhdr *eth;
    struct vlan_hdr *vlan;
    struct iphdr *ip;
    struct lcchdr_ack *lcc;
    struct lcchdr *lcc_data;

    char *updaterule;
    int flow_id = 0;

    while (1)
    {
        //msgs_completed_recv = ibv_poll_cq(cq_recv, 1, &wc_recv);
        msgs_completed_recv = ibv_exp_poll_cq(cq_recv, 1, &wc_exp_recv, sizeof(struct ibv_exp_wc));
        if (msgs_completed_recv > 0)
        {
            eth = (struct ethhdr *)((char *)buf_recv + wc_exp_recv.wr_id * ENTRY_SIZE);
            vlan = (struct vlan_hdr *)(eth + 1);
            ip = (struct iphdr *)(vlan + 1);
            lcc = (struct lcchdr_ack *)(ip + 1);

            //printf("seq: %d\n", lcc->seq);
            //If ack request is tagged
            if (lcc->ack == 1)
            {
                time_now_app = g_time;
                time_now_hw = ibv_exp_cqe_ts_to_ns(&values.clock_info, wc_exp_recv.timestamp);

                while (sent_queue_head == sent_queue_tail)
                {
                }
                if (sent_queue_head != sent_queue_tail)
                {
                    seq = sent_queue[sent_queue_head].seq;
                    sent_time_app = sent_queue[sent_queue_head].sent_time_app;
                    sent_time_hw = sent_queue[sent_queue_head].sent_time_hw;
                    sent_queue_head = (sent_queue_head + 1) % SENT_QUEUE_LENGTH;

                    g_rtt_hw = time_now_hw - sent_time_hw;

                    if (lcc->seq != seq)
                    {
                        fprintf(stderr, "Drop detected!\nSEQ: %d\nNext SEQ: %d\nACK_INV: %d\n\n", lcc->seq, seq, g_ack_req_inv);
                        //exit(1);
                    }
                }
                else
                {
                    fprintf(stderr, "Ack buffer full!!\n");
                }

                if (lcc->endofdata == 1)
                {
                    if (lcc->seq == 0)
                        g_fct = g_rtt_hw;
                    else
                        g_fct = time_now_hw - g_flow_start;
                    g_send_rate = 9.5;
                    if (g_cc_mode == LCC || g_cc_mode == STREAM)
                        g_time_require = (double)DATA_PACKET_SIZE * 8.0 / (g_send_rate / NUM_SEND_THREAD);
                    else
                        g_time_require = (double)DATA_PACKET_SIZE * 8.0 * 16 / (g_send_rate / NUM_SEND_THREAD);

                    pthread_mutex_lock(&mutex_flow_complete_flag);
                    g_flow_active = false;
                    pthread_mutex_unlock(&mutex_flow_complete_flag);
                    flow_id++;
                    ibv_post_recv(qp, &wr_recv[wc_exp_recv.wr_id], &bad_wr_recv);

                    continue;
                }

                if (lcc->seq == 0)
                {
                    g_flow_start = sent_time_hw;
                    time_prev = lcc->ack_time;
                    prev_seq = lcc->seq;
                    prev_rtt = g_rtt_hw;
                    prev_rate_diff = rate_diff;
                    ibv_post_recv(qp, &wr_recv[wc_exp_recv.wr_id], &bad_wr_recv);
                    continue;
                }

                time_start = lcc->ack_time;
                if (time_start >= time_prev)
                    time_taken = time_start - time_prev;
                else
                    time_taken = time_start + 1 * 1e9 - time_prev;

                rate_curr = (double)8.0 * DATA_PACKET_SIZE * (lcc->seq - prev_seq) / time_taken;

                //LCC
                g_recv_rate = rate_curr * 0.8 + 0.2 * g_recv_rate;
                rate_diff = (g_send_rate - rate_curr);
                rate_diff_grad = rate_diff - prev_rate_diff;
                g_rate_diff = rate_diff * 0.7 + 0.3 * g_rate_diff;
                g_rate_diff_grad = rate_diff_grad * 0.7 + 0.3 * g_rate_diff_grad;

                // TIMEY
                new_rtt_diff = g_rtt_hw - prev_rtt;
                rtt_diff = (1 - 0.8) * rtt_diff + 0.8 * new_rtt_diff;
                normalized_gradiant = (double)rtt_diff / (100.0 * 1000.0); //min_rtt;
                g_normalize_gradient = normalized_gradiant;

                if (g_cc_mode == LCC)
                {
                    if (g_rate_diff < 0.05 || g_rate_diff_grad < 0 || g_rtt_hw < 10000)
                    {
                        g_send_rate += 0.05;
                    }
                    else
                    {
                        mN = 0;
                        g_send_rate = g_recv_rate * 0.90;
                    }
                    g_send_rate = MAX(0.2, g_send_rate);
                    g_send_rate = MIN(9.5, g_send_rate);
                    g_time_require = (double)DATA_PACKET_SIZE * 8.0 / (g_send_rate / NUM_SEND_THREAD);
                    //gettimeofday(&val, NULL);
                    //ptm = localtime(&val.tv_sec);
                    //fprintf(fp, "%02d%02d%02d.%06ld, %f, %f ,%ld, %f, %f, %ld, %ld\n", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, val.tv_usec, g_recv_rate, g_send_rate, g_rtt_hw, g_rate_diff_grad, g_rate_diff, time_now_app, sent_time_app);
                }
                else if (g_cc_mode == TIMELY)
                {
                    if (g_rtt_hw < 50 * 1000 /*m_t_low*/)
                    {
                        mN++;
                        updaterule = "t_low";
                        g_send_rate += 0.01; //m_newRate = m_rate + m_delta;
                    }
                    else if (g_rtt_hw > 500 * 1000) //m_t_high)
                    {
                        updaterule = "t_high";
                        g_send_rate = g_send_rate * (1 - 0.8 * (1 - 500 * 1000 / g_rtt_hw)); //m_newRate = m_rate * (1 - m_beta * (1 - m_t_high / m_new_rtt));
                    }
                    else if (normalized_gradiant < 0)
                    {
                        mN++;
                        updaterule = "negative_grad";
                        if (mN > 4)
                            g_send_rate += 5 * 0.01; //  m_newRate = m_rate + m_N * m_delta;
                        else
                            g_send_rate += 0.01;
                    }
                    else
                    {
                        mN = 0;
                        updaterule = "pos_grad";
                        g_send_rate = g_send_rate * (1 - 0.8 * normalized_gradiant); //m_newRate = m_rate * (1 - m_beta * normalized_gradiant);
                    }
                    g_send_rate = MAX(0.2, g_send_rate);
                    g_send_rate = MIN(9.5, g_send_rate);
                    g_time_require = (double)DATA_PACKET_SIZE * 8.0 * 16 / (g_send_rate / NUM_SEND_THREAD);

                    //gettimeofday(&val, NULL);
                    //ptm = localtime(&val.tv_sec);
                    //fprintf(fp, "%02d%02d%02d.%06ld, %f, %f ,%ld\n", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, val.tv_usec, g_recv_rate, g_send_rate, g_rtt_hw);
                }

                gettimeofday(&val, NULL);
                ptm = localtime(&val.tv_sec);
                fprintf(fp, "%02d%02d%02d.%06ld, %f, %f ,%ld\n", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, val.tv_usec, g_recv_rate, g_send_rate, g_rtt_hw);

                time_prev = lcc->ack_time;
                prev_seq = lcc->seq;
                prev_rtt = g_rtt_hw;
                prev_rate_diff = rate_diff;
            }
            else
            {
                fprintf(stderr, "Invalid packet recieved!\n");
            }
            ibv_post_recv(qp, &wr_recv[wc_exp_recv.wr_id], &bad_wr_recv);
        }
        else if (msgs_completed_recv < 0)
        {
            fprintf(stderr, "Polling error\n");
            exit(1);
        }
    }
}

void *recv_data(void *thread_arg)
{
    struct Thread_arg *args = (struct Thread_arg *)thread_arg;
    int thread_id = args->thread_id;
    int thread_action = args->thread_action;

    //unsigned long mask = 2;
    //if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    // {
    //    fprintf(stderr, "Couldn't allocate thread cpu \n");
    //}

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
        .send_cq = cq_recv,
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
    void *buf_recv; //recving buffer address
    buf_recv = malloc(buf_size_recv);
    if (!buf_recv)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr_recv;
    mr_recv = ibv_reg_mr(pd, buf_recv, buf_size_recv, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_recv)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    //Work request(WR)
    struct ibv_sge sg_entry_recv[RQ_NUM_DESC];
    struct ibv_recv_wr wr_recv[RQ_NUM_DESC], *bad_wr_recv;
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
                                                                                                  .dst_mac[0] = g_recv_mac_addr[0],
                                                                                                  .dst_mac[1] = g_recv_mac_addr[1],
                                                                                                  .dst_mac[2] = g_recv_mac_addr[2],
                                                                                                  .dst_mac[3] = g_recv_mac_addr[3],
                                                                                                  .dst_mac[4] = g_recv_mac_addr[4],
                                                                                                  .dst_mac[5] = g_recv_mac_addr[5],
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

    FILE *fp = fopen("trace_rtt.out", "w");
    fprintf(fp, "time, rate_recv, rate_send, rtt_hw, g_rate_diff_grad, g_rate_diff, time_now_app, sent_time_app\n");

    uint64_t wr_id = 0;

    int msgs_completed_recv;
    int mN = 0;

    uint8_t client_ip[4];

    uint32_t time_start;
    uint32_t time_prev = 0;
    uint32_t prev_seq = 0;
    uint32_t seq;
    uint32_t time_now_hw;
    uint32_t sent_time_hw;

    double rate_curr;
    double rate_diff;
    double prev_rate_diff = 0;
    double rate_diff_grad = 0;
    double normalized_gradiant;

    long time_taken = 0;
    long sent_time_app;
    long time_now_app;
    long prev_rtt;
    long new_rtt_diff;
    long rtt_diff;

    struct timeval val;
    struct tm *ptm;
    struct ethhdr *eth;
    struct vlan_hdr *vlan;
    struct iphdr *ip;
    struct lcchdr *lcc_data;

    char *updaterule;

    while (1)
    {
        //msgs_completed_recv = ibv_poll_cq(cq_recv, 1, &wc_recv);
        msgs_completed_recv = ibv_exp_poll_cq(cq_recv, 1, &wc_exp_recv, sizeof(struct ibv_exp_wc));
        if (msgs_completed_recv > 0)
        {

            eth = (struct ethhdr *)((char *)buf_recv + wc_exp_recv.wr_id * ENTRY_SIZE);
            vlan = (struct vlan_hdr *)(eth + 1);
            ip = (struct iphdr *)(vlan + 1);
            lcc_data = (struct lcchdr *)(ip + 1);

            if (lcc_data->data == 1)
            {
                g_total_recv += wc_exp_recv.byte_len;

                if (lcc_data->ackReq == 1)
                {
                    //pthread_mutex_lock(&mutex_sender_thread);
                    while (data_allow_queue_head == data_allow_queue_tail)
                    {
                    }
                    wr_id = data_allow_queue[data_allow_queue_head].wr_id;
                    data_allow_queue_head = (data_allow_queue_head + 1) % DATA_QUEUE_LENGTH;
                    //pthread_mutex_unlock(&mutex_sender_thread);

                    while ((ack_queue_tail + 1) % ACK_QUEUE_LENGTH == ack_queue_head) // || data_allow_queue_head == data_allow_queue_tail)
                    {
                    }

                    memcpy(client_ip, &ip->saddr, 4);
                    create_ack_packet(buf_send + wr_id * ENTRY_SIZE, lcc_data->seq, ibv_exp_cqe_ts_to_ns(&values.clock_info, wc_exp_recv.timestamp), client_ip);
                    ack_queue[ack_queue_tail].buf = buf_send + wr_id * ENTRY_SIZE;
                    ack_queue[ack_queue_tail].wr_id = wr_id;
                    ack_queue_tail = (ack_queue_tail + 1) % ACK_QUEUE_LENGTH;
                }
            }
            else
            {
                fprintf(stderr, "Invalid packet received!\n");
            }
            ibv_post_recv(qp, &wr_recv[wc_exp_recv.wr_id], &bad_wr_recv);
        }
        else if (msgs_completed_recv < 0)
        {
            fprintf(stderr, "Polling error\n");
            exit(1);
        }
    }
}

int main()
{

    char readBuff[512];
    char varBuff[256];

    FILE *fp;

    memset(varBuff, 0, 256);
    printf("\n Reading Conf file...\n\n");
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
                g_vlan_hdr_data = g_vlan_id + (3 << 13);
                g_vlan_hdr_ack = g_vlan_id;
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
            if (strncasecmp(readBuff, "RECV_MAC", strlen("RECV_MAC")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
                       &g_recv_mac_addr[0], &g_recv_mac_addr[1], &g_recv_mac_addr[2],
                       &g_recv_mac_addr[3], &g_recv_mac_addr[4], &g_recv_mac_addr[5]);
                printf("\n RECV_MAC : %s", varBuff);
            }
            if (strncasecmp(readBuff, "SRC_IP", strlen("SRC_IP")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhd.%hhd.%hhd.%hhd",
                       &g_src_ip[0], &g_src_ip[1], &g_src_ip[2], &g_src_ip[3]);
                printf(" SRC_IP : %s", varBuff);
            }
            if (strncasecmp(readBuff, "RECV_IP", strlen("RECV_IP")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhd.%hhd.%hhd.%hhd",
                       &g_recv_ip[0], &g_recv_ip[1], &g_recv_ip[2], &g_recv_ip[3]);
                printf(" RECV_IP : %s", varBuff);
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
            if (strncasecmp(readBuff, "NUM_FLOWS", strlen("NUM_FLOWS")) == 0)
            {
                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%d", &g_num_flows);
                printf("\n NUM_FLOWS : %d", g_num_flows);
            }
            if (strncasecmp(readBuff, "PROCESS", strlen("PROCESS")) == 0)
            {
                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%d", &g_process);
                printf("\n PROCESS : %d", g_process);
                g_process = g_process * 8;
            }
            if (strncasecmp(readBuff, "RAND_SEED", strlen("RAND_SEED")) == 0)
            {
                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%d", &g_seed);
                printf("\n RAND_SEED : %d", g_seed);
            }
            if (strncasecmp(readBuff, "CC_MODE", strlen("CC_MODE")) == 0)
            {
                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                if (strncasecmp(varBuff, "LCC", strlen("LCC")) == 0)
                {
                    g_cc_mode = LCC;
                    printf("\n Congestion control: LCC\n");
                }
                else if (strncasecmp(varBuff, "TIMELY", strlen("TIMELY")) == 0)
                {
                    g_cc_mode = TIMELY;
                    printf("\n Congestion control: TIMELY\n");
                }
                else if (strncasecmp(varBuff, "STREAM", strlen("STREAM")) == 0)
                {
                    g_cc_mode = STREAM;
                    printf("\n Congestion control: STREAM\n");
                }
                else if (strncasecmp(varBuff, "RECV", strlen("RECV")) == 0)
                    g_cc_mode = RECV;
                else
                {
                    fprintf(stderr, "Congestion control mode invalid!!\n Use one of LCC, TIMELY, STREAM ");
                    exit(1);
                }
            }
            if (strncasecmp(readBuff, "FLOW_MODE", strlen("OPER_MODE")) == 0)
            {
                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                if (strncasecmp(varBuff, "INFINITE", strlen("INFINITE")) == 0)
                {
                    g_flow_mode = INFINITE;
                    printf("Flow mode: INFINTE\n");
                }
                else if (strncasecmp(varBuff, "DYNAMIC", strlen("DYNAMIC")) == 0)
                {
                    g_flow_mode = DYNAMIC;
                    printf("Flow mode: DYNAMIC\n");
                }
                else
                {
                    fprintf(stderr, "Flow mode invalid!!\n Use one of INFINITE, TIMELY, DYNAMIC ");
                    exit(1);
                }
            }
        }
    }
    printf("\n\n Read End...\n\n");

    loadCDF(INPUT_CDF_FILE);

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

    pthread_t recv_ack_tread;
    struct Thread_arg recv_thread_arg;
    recv_thread_arg.thread_id = 0;
    recv_thread_arg.thread_action = RECEIVING_ONLY;
    pthread_create(&recv_ack_tread, NULL, recv_ack, &recv_thread_arg);

    //pthread_t recv_data_tread;

    //pthread_create(&recv_data_tread, NULL, recv_data, &recv_thread_arg);

    pthread_t send_thread;
    pthread_create(&send_thread, NULL, send_packet, NULL);

    srand(g_seed);
    printf("\n\n\n %d, %d\n", rand(), g_seed);
    //sleep(2);
    usleep((rand() % 100) * 1000 + 2 * 1000 * 1000); //+ 2 * 1000 * 1000);

    pthread_t send_packet_tread;
    pthread_create(&send_packet_tread, NULL, send_data, NULL);

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
        {
            sleep_cnt++;
        }
        if (sleep_cnt > 10000)
        {
            printf("%02d%02d%02d.%06ld, %f, %f, %ld, %d, %d, %ld\n", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, val.tv_usec, g_recv_rate, g_send_rate, g_rtt_hw, g_ack_req_inv, g_flow_id, g_flow_size);
            sleep_cnt = 0;
        }
    }
}
