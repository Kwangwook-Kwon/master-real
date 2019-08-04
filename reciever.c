#include <infiniband/verbs.h>
#include <infiniband/verbs_exp.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#define PORT_NUM 1
#define ENTRY_SIZE 9000  /* The maximum size of each received packet - set to jumbo frame */
#define RQ_NUM_DESC 2048 /* The maximum receive ring length without processing */

/* The MAC we are listening to. In case your setup is via a network switch, you may need to change the MAC address to suit the network port MAC */

#define DEST_MAC                           \
    {                                      \
        0x50, 0x6b, 0x4b, 0x11, 0x11, 0x22 \
    }

#define SRC_MAC 0x50, 0x6b, 0x4b, 0x11, 0x11, 0x22
#define DST_MAC 0x24, 0x8a, 0x07, 0xcb, 0x48, 0x08
#define ETH_TYPE_VLAN 0x81, 0x00
#define VLAN_HDR 0x60, 0x09
#define ETH_TYPE 0x08, 0x00
#define IP_HDRS 0x45, 0x00, 0x03, 0xe6, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x10, 0x02
#define DST_IP 0x0a, 0x00, 0x09, 0x03
#define SRC_IP 0x0a, 0x00, 0x0a, 0x03
#define UDP_HDR 0x4a, 0x48, 0x04, 0xd4, 0x03, 0xd2, 0xff, 0xa5
#define IP_OPT 0x08, 0x00, 0x49, 0xa4, 0x88
#define ICMP_HDR 0x2c, 0x00, 0x09
char packet[] = {
    DST_MAC,
    SRC_MAC,
    ETH_TYPE_VLAN,
    VLAN_HDR,
    ETH_TYPE,
    IP_HDRS,
    SRC_IP,
    DST_IP,
    UDP_HDR,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
    0x38,
};

struct ibv_device **dev_list;
struct ibv_device *ib_dev;
struct ibv_context *context;
struct ibv_pd *pd;

uint64_t total_recv;

void *revieving_function()
{
    int ret;
    /* 4. Create Complition Queue (CQ) */
    struct ibv_cq *cq, *cq_send;
    cq = ibv_create_cq(context, RQ_NUM_DESC, NULL, NULL, 0);
    cq_send = ibv_create_cq(context, RQ_NUM_DESC, NULL, NULL, 0);

    if (!cq)
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
        .recv_cq = cq,
        .cap = {
            /* no send ring */
            .max_send_wr = RQ_NUM_DESC,
            /* maximum number of packets in ring */
            .max_recv_wr = RQ_NUM_DESC,
            /* only one pointer per descriptor */
            .max_recv_sge = 1,
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
    int buf_size = ENTRY_SIZE * RQ_NUM_DESC; /* maximum size of data to be accessed by hardware */
    void *buf, *buf_send;
    buf = malloc(buf_size);
    buf_send = malloc(buf_size);
    if (!buf || !buf_send)
    {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    /* 10. Register the user memory so it can be accessed by the HW directly */
    struct ibv_mr *mr, *mr_send;
    mr = ibv_reg_mr(pd, buf, buf_size, IBV_ACCESS_LOCAL_WRITE);
    mr_send = ibv_reg_mr(pd, buf_send, buf_size, IBV_ACCESS_LOCAL_WRITE);
    if (!mr) //|| !mr_send)
    {
        fprintf(stderr, "Couldn't register mr\n");
        exit(1);
    }

    /* 11. Attach all buffers to the ring */
    memcpy(buf_send, packet, sizeof(packet));

    int n;
    struct ibv_sge sg_entry, sg_entry_send;
    struct ibv_recv_wr wr, *bad_wr;
    struct ibv_send_wr wr_send, *bad_wr_send;

    sg_entry_send.addr = (uint64_t)buf_send;
    sg_entry_send.length = sizeof(packet);
    sg_entry_send.lkey = mr_send->lkey;
    memset(&wr_send, 0, sizeof(wr_send));
    wr_send.num_sge = 1;
    wr_send.sg_list = &sg_entry_send;
    wr_send.next = NULL;
    wr_send.opcode = IBV_WR_SEND;
    wr_send.send_flags = IBV_SEND_SIGNALED;

    /* pointer to packet buffer size and memory key of each packet buffer */
    sg_entry.length = ENTRY_SIZE;
    sg_entry.lkey = mr->lkey;
    /*
    * descriptor for receive transaction - details:
    * - how many pointers to receive buffers to use
    * - if this is a single descriptor or a list (next == NULL single)
    */

    wr.num_sge = 1;
    wr.sg_list = &sg_entry;
    wr.next = NULL;
    for (n = 0; n < RQ_NUM_DESC; n++)
    {
        /* each descriptor points to max MTU size buffer */
        sg_entry.addr = (uint64_t)buf + ENTRY_SIZE * n;

        /* index of descriptor returned when packet arrives */
        wr.wr_id = n;

        ibv_post_recv(qp, &wr, &bad_wr);
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
                                                                                                  .dst_mac = DEST_MAC,
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
        /*.spec_ipv4 = {
            .type = IBV_FLOW_SPEC_IPV4, 
            .size = sizeof(struct ibv_flow_spec_ipv4),
            .val = {
                .src_ip = 0,
                .dst_ip = 0x0A000A03,
            },
        .mask = {
            .src_ip = 0,
            .dst_ip = 0xFFFFFFFF,
        }*/
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
    int msgs_completed;
    struct ibv_wc wc;
    unsigned char *output;
    while (1)
    {

        /* wait for completion */
        msgs_completed = ibv_poll_cq(cq, 1, &wc);
        if (msgs_completed > 0)
        {
            /*
             * completion includes: 
             * -status of descriptor
             * -index of descriptor completing
             * -size of the incoming packets
             */
            total_recv += wc.byte_len;
            //printf("\n\n");
            //printf("message %ld received size %d\n", wc.wr_id, wc.byte_len);
            //output = (char *)buf + wc.wr_id * ENTRY_SIZE;
            //for (int i = 0; i < wc.byte_len; i++)
            //{
            //    printf("%02X ", output[i]);
            //    if (i % 16 == 0 && i != 0)
            //        printf("\n");
            //}
            //printf("\n\n\n");

            sg_entry.addr = (uint64_t)buf + wc.wr_id * ENTRY_SIZE;
            wr.wr_id = wc.wr_id;
            //memcpy(buf_send, packet, sizeof(packet));
            ret = ibv_post_send(qp, &wr_send, &bad_wr_send);
            if (ret < 0)
            {
                fprintf(stderr, "failed in post send\n");
                exit(1);
            }
            msgs_completed = ibv_poll_cq(cq_send, 1, &wc);
            /* after processed need to post back buffer */

            ibv_post_recv(qp, &wr, &bad_wr);
        }
        else if (msgs_completed < 0)
        {
            printf("Polling error\n");
            exit(1);
        }
    }
}

int main()
{
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

    /* 4. Create sending threads */
    pthread_t p_thread[1];
    int thread_id[1];
    for (int i = 0; i < 1; i++)
    {
        thread_id[i] = i;
        pthread_create(&p_thread[i], NULL, revieving_function, NULL);
    }
    total_recv = 0;
    double time_require = 0.050;
    struct timespec start, previous;
    previous.tv_sec = 0;
    previous.tv_nsec = 0;
    double time_taken = -1;
    while (1)
    {
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (time_taken >= 0)
        {
            time_taken += (start.tv_sec - previous.tv_sec) * 1e9;
            time_taken += (start.tv_nsec - previous.tv_nsec) * 1e-9; //add 0.1 nano secondes becuase CPU cannot measure per pico seconds.
            previous.tv_sec = start.tv_sec;
            previous.tv_nsec = start.tv_nsec;
        }
        if (time_taken >= time_require || time_taken == -1)
        {
            time_taken = 0;
            printf("\nBandwidth : %2.5f", total_recv * 8 / (time_require * 1000 * 1000 * 1000));
            total_recv = 0;
        }
    }

    printf("We are done\n");

    return 0;
}