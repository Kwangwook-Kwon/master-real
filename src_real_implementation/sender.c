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
    size_t lcc_len = ip_len - sizeof(struct iphdr);
    lcc->source = UDP_SRC;
    lcc->dest = UDP_DST;
    lcc->len = htons((uint16_t)lcc_len);
    lcc->check = 0; //Zero means no checksum check at revciever
    lcc->data = 1;
    lcc->seq = g_send_seq;
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
    memcpy(eth->h_dest, g_dst_mac_addr, ETH_ALEN);
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
    //if(packet_type == DATA)
    sg_entry->length = DATA_PACKET_SIZE;
    //else if(packet_type == DUMMY)
    //    sg_entry->length = 10;
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

    /* Register steering rule to intercept packet to DEST_MAC and place packet in ring pointed by ->qp */

    /*flow_attr->attr.comp_mask = 0;
    flow_attr->attr.type = IBV_FLOW_ATTR_NORMAL;
    flow_attr->attr.size = sizeof(struct ibv_flow_attr);
    flow_attr->attr.priority = 0;
    flow_attr->attr.num_of_specs = 1;
    flow_attr->attr.port = PORT_NUM;
    flow_attr->attr.flags = 0;

    flow_attr->spec_eth.type = IBV_EXP_FLOW_SPEC_ETH;
    flow_attr->spec_eth.size = sizeof(struct ibv_flow_spec_eth);
    memcpy(&flow_attr->spec_eth.val.dst_mac, g_eth_pause_addr, ETH_ALEN);
    memset(&flow_attr->spec_eth.val.src_mac, 0, ETH_ALEN);
    flow_attr->spec_eth.val.ether_type = ETH_P_PAUSE;
    flow_attr->spec_eth.val.vlan_tag = 0;

    memset(&flow_attr->spec_eth.mask.dst_mac, 0xFF, ETH_ALEN);
    memset(&flow_attr->spec_eth.mask.src_mac, 0x00, ETH_ALEN);

    flow_attr->spec_eth.mask.ether_type = 0;
    flow_attr->spec_eth.mask.vlan_tag = 0;*/
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

void *thread_fucntion(void *thread_arg)
{
    struct Thread_arg *args = (struct Thread_arg *)thread_arg;
    int thread_id = args->thread_id;
    int thread_action = args->thread_action;

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
    buf_send = malloc(buf_size);
    buf_recv = malloc(buf_size);
    if (!buf_send || !buf_recv)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr_send;
    struct ibv_mr *mr_recv;
    mr_send = ibv_reg_mr(pd, buf_send, buf_size, IBV_ACCESS_LOCAL_WRITE);
    mr_recv = ibv_reg_mr(pd, buf_recv, buf_size, IBV_ACCESS_LOCAL_WRITE);
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
                                                                                                  .dst_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                                                                                  .src_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                                                                                  .ether_type = 0x8808,
                                                                                                  .vlan_tag = 0,
                                                                                              },
                     .mask = {
                         .dst_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                         .src_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                         .ether_type = 0xFFFF,
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
    sleep(2);

    uint64_t wr_id = 0;
    int msgs_completed_send = 0;
    int msgs_completed_recv;
    struct timespec start, previous;
    previous.tv_sec = 0;
    previous.tv_nsec = 0;
    double time_taken = -1;
    uint64_t transmitted_data = 0;
    double time_diff = 0;
    double time_require = (double)DATA_PACKET_SIZE * 8.0 * 1e-9 / (SENDING_RATE_IN_GIGA / NUM_SEND_THREAD);
    printf("\n Thread %d Loop Started\n", thread_id);
    //msgs_completed_send = ibv_poll_cq(cq_send, 1, &wc);

    while (1)
    {

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (time_taken >= 0)
        {
            time_taken += (start.tv_sec - previous.tv_sec) * 1e9;
            time_taken += (start.tv_nsec - previous.tv_nsec + 0.5 ) * 1e-9; //add 0.1 nano secondes becuase CPU cannot measure per pico seconds.
            previous.tv_sec = start.tv_sec;
            previous.tv_nsec = start.tv_nsec;
        }
        if(msgs_completed_send == 0)
        {
             msgs_completed_send = ibv_poll_cq(cq_send, 1, &wc);
        } //while (msgs_completed_send == 0);

        if ( (time_taken >= time_require || time_taken == -1) &&  msgs_completed_send > 0)
        {
            //Sending procedure
            wr_id = wc.wr_id;
            create_data_packet(buf_send + wr_id * ENTRY_SIZE);
            create_send_work_request(wr_send + wc.wr_id, sg_entry_send + wc.wr_id, mr_send, buf_send + wr_id * ENTRY_SIZE, wr_id, DATA);
            ret = ibv_post_send(qp, wr_send + wc.wr_id, &bad_wr_send);
            if (ret < 0)
            {
                fprintf(stderr, "failed in post send\n");
                exit(1);
            }
            transmitted_data += DATA_PACKET_SIZE;
            msgs_completed_send = 0;
            time_taken = 0;
        }
        if (transmitted_data > TOTAL_TRANSMIT_DATA && TOTAL_TRANSMIT_DATA != -1)
            break;
    }
    printf("END!!!\n");
}

int main()
{
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

    /* 3. Allocate Protection Domain */
    /* Allocate a protection domain to group memory regions (MR) and rings */
    pd = ibv_alloc_pd(context);
    if (!pd)
    {
        fprintf(stderr, "Couldn't allocate PD\n");
        exit(1);
    }

    /* 4. Create sending threads */
    pthread_t p_thread[NUM_SEND_THREAD];
    int thread_id[NUM_SEND_THREAD];
    struct Thread_arg *thread_arg = (struct Thread_arg *)malloc(sizeof(struct Thread_arg)*NUM_SEND_THREAD);

    for (int i = 0; i < NUM_SEND_THREAD; i++)
    {
        thread_arg[i].thread_id = i;
        thread_arg[i].thread_action = SENDING_AND_RECEVING;
        pthread_create(&p_thread[i], NULL, thread_fucntion, (void *)(thread_arg+i));
    }

    while (1)
    {
    }

    printf("We are done\n");

    return 0;
}
