#define _GNU_SOURCE
#include <infiniband/verbs.h>
#include <infiniband/verbs_exp.h>
#include <stdbool.h>
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
#include "receiver.h"

void *clock_thread_function()
{

    unsigned long mask = 64;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }
    struct timespec time;
    time.tv_sec = 0;
    time.tv_nsec = 0;
    long time_taken, time_prev, time_start;
    clock_gettime(CLOCK_MONOTONIC, &time);
    g_time = time.tv_nsec;
    time_prev = g_time;

    while (1)
    {
        clock_gettime(CLOCK_MONOTONIC, &time);
        g_time = time.tv_nsec;
        time_start = g_time;
        if (time_start >= time_prev)
            time_taken += (time_start - time_prev);
        else
            time_taken += (time_start + 1 * 1e9 - time_prev);
        time_prev = time_start;
        if (time_taken > 50000 && g_cc_mode == DCQCN)
        {
            time_taken = 0;
            for (int i = 0; i < 8; i++)
            {
                if (cnp_cnt[i] > 0)
                {
                    pthread_mutex_lock(&mutex_ack_queue);
                    cnp_cnt[i] = 0;
                    if ((ack_queue_tail + 1) % ACK_QUEUE_LENGTH == ack_queue_head)
                    {
                        printf("ERROR: ACK queue is full!!\n");
                        exit(1);
                    }
                    ack_queue[ack_queue_tail].endofdata = 0;
                    ack_queue[ack_queue_tail].seq = g_recv_seq;
                    ack_queue[ack_queue_tail].cnp = 1;
                    ack_queue[ack_queue_tail].ack = 0;
                    ack_queue[ack_queue_tail].client_ip[0] = 10;
                    ack_queue[ack_queue_tail].client_ip[1] = 0;
                    ack_queue[ack_queue_tail].client_ip[2] = i + 9;
                    ack_queue[ack_queue_tail].client_ip[3] = 11;
                    ack_queue_tail = (ack_queue_tail + 1) % ACK_QUEUE_LENGTH;
                    pthread_mutex_unlock(&mutex_ack_queue);
                }
            }
        }
    }
}

void create_ack_packet(void *buf, uint32_t seq, uint32_t ack_time, uint8_t *client_ip, bool endofdata, bool cnp, bool ack)
{

    // Ether header
    struct ethhdr *eth = (struct ethhdr *)buf;
    memcpy(eth->h_dest, g_dst_mac_addr, ETH_ALEN);
    memcpy(eth->h_source, g_recv_mac_addr, ETH_ALEN);
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
    ip->tos = 0;
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
    lcc->dest = UDP_DST;
    lcc->len = htons((uint16_t)lcc_len);
    lcc->check = 0; //Zero means no checksum check at revciever
    lcc->ack = ack;
    lcc->seq = seq;
    lcc->ack_time = ack_time;
    lcc->cnp = cnp;
    lcc->endofdata = endofdata;
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
    else if (packet_type == ACK)
        sg_entry->length = ACK_PACKET_SIZE;
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

void *send_packet()
{

    unsigned long mask = 1;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }
    int ret;
    /* 4. Create Complition Queue (CQ) */
    struct ibv_cq *cq_recv, *cq_send;
    //cq_recv = ibv_create_cq(context, RQ_NUM_DESC, NULL, NULL, 0);
    cq_send = ibv_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0);

    if (!cq_send)
    {
        fprintf(stderr, "Couldn't create CQ %d\n", errno);
        exit(1);
    }

    /* 5. Initialize QP */
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_context = NULL,

        /* report receive completion to cq */
        .send_cq = cq_send,
        .recv_cq = cq_send,
        .cap = {
            /* no send ring */
            .max_send_wr = SQ_NUM_DESC,
            /* maximum number of packets in ring */
            .max_recv_wr = 0,
            /* only one pointer per descriptor */
            //.max_recv_sge = 1,
            .max_send_sge = 1,
        },

        .qp_type = IBV_QPT_RAW_PACKET,

    };

    /* 6. Create Queue Pair (QP) - Receive Ring */
    qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp)
    {
        fprintf(stderr, "Couldn't create RSS QP\n");
        exit(1);
    }

    /* 7. Initialize the QP (receive ring) and assign a port */
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

    /* 8. Move ring state to ready to receive, this is needed in order to be able to receive packets */
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

    /* 9. Allocate Memory */
    //buf_size_recv = ENTRY_SIZE * RQ_NUM_DESC;
    buf_size_send = ENTRY_SIZE * SQ_NUM_DESC; /* maximum size of data to be accessed by hardware */
    void *buf_send;
    //buf_recv = malloc(buf_size_recv);
    buf_send = malloc(buf_size_send);
    if (!buf_send)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr_recv, *mr_send;
    //mr_recv = ibv_reg_mr(pd, buf_recv, buf_size_recv, IBV_ACCESS_LOCAL_WRITE);
    mr_send = ibv_reg_mr(pd, buf_send, buf_size_send, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_send)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    /* 11. Attach all buffers to the ring */

    struct ibv_sge sg_entry_send[SQ_NUM_DESC];
    struct ibv_send_wr wr_send[SQ_NUM_DESC], *bad_wr_send;

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

    /*
    * descriptor for receive transaction - details:
    * - how many pointers to receive buffers to use
    * - if this is a single descriptor or a list (next == NULL single)
    */

    /* 14. Wait for CQ event upon message received, and print a message */
    int msgs_completed_recv, msgs_completed_send;
    int wr_id;
    struct ibv_wc wc_recv, wc_send;
    unsigned char *output;
    uint32_t seq, ack_time;
    struct ack_queue_items queue_item;
    uint8_t client_ip[4];
    bool endofdata, cnp, ack;
    do
    {
        msgs_completed_send = ibv_poll_cq(cq_send, 1, &wc_send);
    } while (msgs_completed_send == 0);

    while (1)
    {
        if (ack_queue_head != ack_queue_tail)
        {
            endofdata = ack_queue[ack_queue_head].endofdata;
            seq = ack_queue[ack_queue_head].seq;
            ack_time = ack_queue[ack_queue_head].ack_time;
            cnp = ack_queue[ack_queue_head].cnp;
            ack = ack_queue[ack_queue_head].ack;

            memcpy(client_ip, ack_queue[ack_queue_head].client_ip, 4);
            ack_queue_head = (ack_queue_head + 1) % ACK_QUEUE_LENGTH;

            create_ack_packet(buf_send + wc_send.wr_id * ENTRY_SIZE, seq, ack_time, client_ip, endofdata, cnp, ack);
            create_send_work_request(wr_send + wc_send.wr_id, sg_entry_send + wc_send.wr_id, mr_send, buf_send + wc_send.wr_id * ENTRY_SIZE, wc_send.wr_id, ACK);
            ret = ibv_post_send(qp, wr_send + wc_send.wr_id, &bad_wr_send);
            if (ret < 0)
            {
                fprintf(stderr, "failed in post send\n");
                exit(1);
            }
            do
            {
                msgs_completed_send = ibv_poll_cq(cq_send, 1, &wc_send);
            } while (msgs_completed_send == 0);
        }
    }
}

void *recv_packet(void *thread_arg)
{

    unsigned long mask = 2;
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), (cpu_set_t *)&mask))
    {
        fprintf(stderr, "Couldn't allocate thread cpu \n");
    }
    int ret;
    /* 4. Create Complition Queue (CQ) */

    struct ibv_exp_values values = {0};
    ibv_exp_query_values(context, IBV_EXP_VALUES_CLOCK_INFO, &values);

    struct ibv_cq *cq_recv, *cq_send;
    struct ibv_exp_cq_init_attr cq_init_attr;
    memset(&cq_init_attr, 0, sizeof(cq_init_attr));
    cq_init_attr.flags = IBV_EXP_CQ_TIMESTAMP;
    cq_init_attr.comp_mask = IBV_EXP_CQ_INIT_ATTR_FLAGS;
    cq_recv = ibv_exp_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0, &cq_init_attr);
    //cq_send = ibv_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0);
    //cq_recv = ibv_create_cq(context, RQ_NUM_DESC, NULL, NULL, 0);

    if (!cq_recv) // || !cq_send)
    {
        fprintf(stderr, "Couldn't create CQ %d\n", errno);
        exit(1);
    }

    /* 5. Initialize QP */
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_context = NULL,

        /* report receive completion to cq */
        .send_cq = cq_recv,
        .recv_cq = cq_recv,
        .cap = {
            /* no send ring */
            .max_send_wr = 0,
            /* maximum number of packets in ring */
            .max_recv_wr = RQ_NUM_DESC,
            /* only one pointer per descriptor */
            .max_recv_sge = 1,
            //.max_send_sge = 1,
        },

        .qp_type = IBV_QPT_RAW_PACKET,

    };

    /* 6. Create Queue Pair (QP) - Receive Ring */
    qp = ibv_create_qp(pd, &qp_init_attr);
    if (!qp)
    {
        fprintf(stderr, "Couldn't create RSS QP\n");
        exit(1);
    }

    /* 7. Initialize the QP (receive ring) and assign a port */
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

    /* 8. Move ring state to ready to receive, this is needed in order to be able to receive packets */
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

    /* 9. Allocate Memory */
    buf_size_recv = ENTRY_SIZE * RQ_NUM_DESC;
    //buf_size_recv = ENTRY_SIZE * SQ_NUM_DESC; /* maximum size of data to be accessed by hardware */
    void *buf_recv, *buf_send;
    buf_recv = malloc(buf_size_recv);
    //buf_send = malloc(buf_size_send);
    if (!buf_recv) //|| !buf_send)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr_recv;
    mr_recv = ibv_reg_mr(pd, buf_recv, buf_size_recv, IBV_ACCESS_LOCAL_WRITE);
    //mr_send = ibv_reg_mr(pd, buf_send, buf_size_send, IBV_ACCESS_LOCAL_WRITE);
    if (!mr_recv) //|| !mr_send)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    /* 11. Attach all buffers to the ring */

    struct ibv_sge sg_entry_recv[RQ_NUM_DESC]; //;, sg_entry_send[SQ_NUM_DESC];
    struct ibv_recv_wr wr_recv[RQ_NUM_DESC], *bad_wr_recv;
    //struct ibv_send_wr wr_send[SQ_NUM_DESC], *bad_wr_send;

    /*
    * descriptor for receive transaction - details:
    * - how many pointers to receive buffers to use
    * - if this is a single descriptor or a list (next == NULL single)
    */

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

    /* 12. Register steering rule to intercept packet to DEST_MAC and place packet in ring pointed by ->qp */
    struct raw_eth_flow_attr
    {
        struct ibv_flow_attr attr;
        struct ibv_flow_spec_eth spec_eth;
        //struct ibv_flow_spec_ipv4 spec_ipv4;
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
                         .dst_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
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

    /* 14. Wait for CQ event upon message received, and print a message */
    int msgs_completed_recv, msgs_completed_send;
    int wr_id;
    struct ibv_wc wc_recv, wc_send;
    struct ibv_exp_wc wc_exp_recv;
    unsigned char *output;
    int flow_id = 0;

    struct timespec time, time_prev;
    time.tv_sec = 0;
    time.tv_nsec = 0;

    clock_gettime(CLOCK_MONOTONIC, &time);
    g_time = time.tv_nsec;
    uint16_t time_taken;
    uint8_t addr[4];

    while (1)
    {

        /* wait for completion */
        msgs_completed_recv = ibv_exp_poll_cq(cq_recv, 1, &wc_exp_recv, sizeof(struct ibv_exp_wc));
        if (msgs_completed_recv > 0)
        {
            /*
             * completion includes: 
             * -status of descriptor
             * -index of descriptor completing
             * -size of the incoming packets
             */
            pthread_mutex_lock(&mutex_g_recv_data);
            pthread_mutex_unlock(&mutex_g_recv_data);
            struct ethhdr *eth = (struct ethhdr *)((char *)buf_recv + wc_exp_recv.wr_id * ENTRY_SIZE);
            struct vlan_hdr *vlan = (struct vlan_hdr *)(eth + 1);
            struct iphdr *ip = (struct iphdr *)(vlan + 1);
            struct lcchdr *lcc = (struct lcchdr *)(ip + 1);
            //struct toshdr *tos = (struct toshdr *)&(ip->tos);
            //printf("recved: %d\n", lcc->seq);
            //g_total_recv += wc_exp_recv.byte_len - sizeof(struct ethhdr) - sizeof(struct vlan_hdr) - sizeof(struct iphdr)- sizeof(struct lcchdr);

            if ((ip->tos & 3) == 3 && g_cc_mode == DCQCN)
            {
                memcpy(&addr, &ip->saddr, 4);

                pthread_mutex_lock(&cnp);
                cnp_cnt[addr[2] - 9]++;
                pthread_mutex_unlock(&cnp);
            }
            if (lcc->ackReq == 1)
            {
                //printf("seq: %d\n", lcc->seq);
                pthread_mutex_lock(&mutex_ack_queue);

                if ((ack_queue_tail + 1) % ACK_QUEUE_LENGTH == ack_queue_head)
                {
                    printf("ERROR: ACK queue is full!!\n");
                    exit(1);
                }
                ack_queue[ack_queue_tail].endofdata = lcc->endofdata;
                ack_queue[ack_queue_tail].seq = lcc->seq;
                ack_queue[ack_queue_tail].cnp = 0;
                ack_queue[ack_queue_tail].ack = 1;
                ack_queue[ack_queue_tail].ack_time = ibv_exp_cqe_ts_to_ns(&values.clock_info, wc_exp_recv.timestamp);
                memcpy(&ack_queue[ack_queue_tail].client_ip, &ip->saddr, 4);
                ack_queue_tail = (ack_queue_tail + 1) % ACK_QUEUE_LENGTH;
                pthread_mutex_unlock(&mutex_ack_queue);
            }
            g_recv_seq = lcc->seq;
            ibv_post_recv(qp, &wr_recv[wc_exp_recv.wr_id], &bad_wr_recv);
        }
        else if (msgs_completed_recv < 0)
        {
            printf("Polling error\n");
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
                g_vlan_hdr_ack = g_vlan_id;
            }
            if (strncasecmp(readBuff, "RECV_MAC", strlen("RECV_MAC")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
                       &g_recv_mac_addr[0], &g_recv_mac_addr[1], &g_recv_mac_addr[2],
                       &g_recv_mac_addr[3], &g_recv_mac_addr[4], &g_recv_mac_addr[5]);
            }
            if (strncasecmp(readBuff, "RECV_IP", strlen("RECV_IP")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhd.%hhd.%hhd.%hhd",
                       &g_recv_ip[0], &g_recv_ip[1], &g_recv_ip[2], &g_recv_ip[3]);
            }
            if (strncasecmp(readBuff, "DST_MAC", strlen("DST_MAC")) == 0)
            {

                strcpy(varBuff, strrchr(readBuff, '=') + 1);
                sscanf(varBuff, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
                       &g_dst_mac_addr[0], &g_dst_mac_addr[1], &g_dst_mac_addr[2],
                       &g_dst_mac_addr[3], &g_dst_mac_addr[4], &g_dst_mac_addr[5]);
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
                else if (strncasecmp(varBuff, "DCQCN", strlen("DCQCN")) == 0)
                {
                    g_cc_mode = DCQCN;
                    printf("\n Congestion control: DCQCN\n");
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
        }
    }
    printf("\n\n Read End...\n\n");

    fclose(fp);

    int ret;

    /* Get the list of offload capable devices */
    dev_list = ibv_get_device_list(NULL);
    if (!dev_list)
    {
        perror("Failed to get IB devices list");
        exit(1);
    }

    /* 1. Get Device */
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

    /* 3. Allocate Protection Domain */
    /* Allocate a protection domain to group memory regions (MR) and rings */
    pd = ibv_alloc_pd(context);
    if (!pd)
    {
        fprintf(stderr, "Couldn't allocate PD\n");
        exit(1);
    }

    pthread_t ack_tread;
    pthread_create(&ack_tread, NULL, send_packet, NULL);

    pthread_t clock_thread;
    pthread_create(&clock_thread, NULL, clock_thread_function, NULL);

    /* 4. Create sending threads */
    pthread_t p_thread[1];
    int thread_id[1];
    struct Thread_arg *thread_arg = (struct Thread_arg *)malloc(sizeof(struct Thread_arg) * NUM_SEND_THREAD);

    for (int i = 0; i < 1; i++)
    {
        thread_arg[i].thread_id = i;
        thread_arg[i].thread_action = SENDING_AND_RECEVING;
        pthread_create(&p_thread[i], NULL, recv_packet, (void *)(thread_arg + i));
    }
    double time_require = 10;
    struct timespec start, previous;
    previous.tv_sec = 0;
    previous.tv_nsec = 0;
    double time_taken = -1;
    struct timeval val;
    fp = fopen("trace_recv.out", "w");
    int cnt = 0;
    struct tm *ptm;
    while (1)
    {
        /*gettimeofday(&val, NULL);
        ptm = localtime(&val.tv_sec);
        usleep(time_require * 1000);
        if (g_total_recv > 0)
        {
            fprintf(fp, "%02d%02d%02d.%06ld, %f\n", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, val.tv_usec, g_total_recv * 8 / (time_require * 1000 * 1000));
            cnt++;
            if (cnt > 100)
            {
                printf("Bandwidth : %2.5f\n", g_total_recv * 8 / (time_require * 1000 * 1000));
                cnt = 0;
            }
            pthread_mutex_lock(&mutex_g_recv_data);
            g_total_recv = 0;
            pthread_mutex_unlock(&mutex_g_recv_data);
        }*/
        sleep(100);
    }

    printf("We are done\n");

    return 0;
}