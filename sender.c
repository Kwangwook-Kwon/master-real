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
    ip->check = gen_checksum((char *)ip, sizeof(struct iphdr));

    //LCC Header
    struct lcchdr *lcc = (struct lcchdr *)(ip + 1);
    memset(lcc,0,sizeof(struct lcchdr));
    size_t lcc_len = ip_len - sizeof(struct iphdr);
    lcc->source = UDP_SRC;
    lcc->dest = UDP_DST;
    lcc->len = lcc_len;
    lcc->check = 0;    //Zero means no checksum check at revciever
    lcc ->data = 1;

    // Payload : Data
    void *payload = lcc + 1;
    char D ='D';
    memset(payload, D , lcc_len - sizeof(struct lcchdr) );
}

static uint16_t gen_checksum(const char *buf, int num_bytes)
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


void *sending_fucntion(void *id)
{
    void *buf;                               //sending buffer address
    int ret;
    int thread_id = *((int *)id);
    /* 4. Create Complition Queue (CQ) */
    struct ibv_cq *cq;
    cq = ibv_create_cq(context, SQ_NUM_DESC, NULL, NULL, 0);
    if (!cq)
    {
        fprintf(stderr, "Couldn't create CQ %d\n", errno);
        exit(1);
    }

    /* 5. Initialize QP */
    struct ibv_qp *qp;
    struct ibv_qp_init_attr qp_init_attr = {
        .qp_context = NULL,
        /* report send completion to cq */
        .send_cq = cq,
        .recv_cq = cq,
        .cap = {
            /* number of allowed outstanding sends without waiting for a completion */
            .max_send_wr = SQ_NUM_DESC,
            /* maximum number of pointers in each descriptor */
            .max_send_sge = 1,
            /* if inline maximum of payload data in the descriptors themselves */
            //.max_inline_data = 970,
            .max_recv_wr = 0},
        .qp_type = IBV_QPT_RAW_PACKET,
    };

    /* 6. Create Queue Pair (QP) - Send Ring */
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

    /* 8. Move the ring to ready to send in two steps (a,b) */
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

    /* 9. Allocate Memory */
    buf = malloc(buf_size);
    if (!buf)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr;
    mr = ibv_reg_mr(pd, buf, buf_size, IBV_ACCESS_LOCAL_WRITE);
    if (!mr)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    //memcpy(buf, packet, sizeof(packet));
    unsigned int n;
    struct ibv_sge sg_entry;
    struct ibv_send_wr wr, *bad_wr;
    int msgs_completed;
    struct ibv_wc wc;
    /* scatter/gather entry describes location and size of data to send*/
    sg_entry.addr = (uint64_t)buf;
    sg_entry.length = DATA_PACKET_SIZE;
    sg_entry.lkey = mr->lkey;
    memset(&wr, 0, sizeof(wr));
    /*
     * descriptor for send transaction - details:
     * - how many pointer to data to use
     * - if this is a single descriptor or a list (next == NULL single)
     * - if we want inline and/or completion
     */

    wr.num_sge = 1;
    wr.sg_list = &sg_entry;
    wr.next = NULL;
    wr.opcode = IBV_WR_SEND;
    wr.send_flags = IBV_SEND_SIGNALED;

    struct timespec start, previous;
    previous.tv_sec = 0;
    previous.tv_nsec = 0;
    double time_taken = -1;
    uint64_t rate_m = 10 * 1000;
    double time_diff = 0;
    double time_require = (double)DATA_PACKET_SIZE * 8.0 * 1e-9 / (SENDING_RATE_IN_GIGA / NUM_SEND_THREAD);
    printf("time_require : %20.20f\n", time_require);
    while (1)
    {
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (time_taken >= 0)
        {
            time_taken += (start.tv_sec - previous.tv_sec) * 1e9;
            time_taken += (start.tv_nsec - previous.tv_nsec + 0.5) * 1e-9; //add 0.1 nano secondes becuase CPU cannot measure per pico seconds.
            previous.tv_sec = start.tv_sec;
            previous.tv_nsec = start.tv_nsec;
        }
        if (time_taken >= time_require || time_taken == -1)
        {
            time_diff = time_taken - time_require;
            //if(time_diff >= 0 ){
            //    time_taken = time_diff;}
            //else{
            time_taken = 0; //}

            create_data_packet(buf);
            ret = ibv_post_send(qp, &wr, &bad_wr);
            if (ret < 0)
            {
                fprintf(stderr, "failed in post send\n");
                exit(1);
            }

            msgs_completed = ibv_poll_cq(cq, 1, &wc);

            if (msgs_completed < 0)
            {
                printf("Polling error\n");
                exit(1);
            }
        }
    }
}

int main()
{
    //printf("\n\nSize of Seinding Packet : %ld\n\n", sizeof(packet));
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
    for (int i = 0; i < NUM_SEND_THREAD; i++)
    {
        thread_id[i] = i;
        pthread_create(&p_thread[i], NULL, sending_fucntion, (void *)thread_id + i * sizeof(int));
    }

    while (1)
    {
    }

    printf("We are done\n");

    return 0;
}
