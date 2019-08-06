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

#define PORT_NUM 1
#define ENTRY_SIZE 9000  /* maximum size of each send buffer */
#define SQ_NUM_DESC 2048 /* maximum number of sends waiting for completion */
#define RQ_NUM_DESC 2048
#define NUM_SEND_THREAD 5
#define SENDING_RATE_IN_GIGA 10
#define DATA_PACKET_SIZE 1500
#define TOTAL_TRANSMIT_DATA -1

/* template of packet to send */
#define DST_MAC 0x24, 0x8a, 0x07, 0xcb, 0x48, 0x08
#define SRC_MAC 0x50, 0x6b, 0x4b, 0x11, 0x11, 0x11
#define PAUSE_ETH_DST_ADDR 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01
 
#define VLAN_HDR 0x60, 0x09 // Priority 3show

#define SRC_IP 0x0a, 0x00, 0x09, 0x03
#define DST_IP 0x0a, 0x00, 0x0a, 0x03

#define UDP_SRC 12357
#define UDP_DST 12358

enum Thread_action
{
    SENDING_AND_RECEVING,
    SENDING_ONLY,
    RECEIVING_ONLY
};

enum Packet_type
{
    DATA,
    DUMMY
};

struct ibv_pd *pd;
struct ibv_device **dev_list;
struct ibv_device *ib_dev;
struct ibv_context *context;

struct Thread_arg
{
    int thread_id;
    enum Thread_action thread_action;
};

struct raw_eth_flow_attr
{
    struct ibv_flow_attr attr;
    struct ibv_flow_spec_eth spec_eth;
};

int buf_size = ENTRY_SIZE * SQ_NUM_DESC; /* maximum size of data to be access directly by hw */

static uint8_t g_dst_mac_addr[ETH_ALEN] = {DST_MAC};
static uint8_t g_src_mac_addr[ETH_ALEN] = {SRC_MAC};
static uint8_t g_brd_mac_addr[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t g_eth_pause_addr[ETH_ALEN] = {PAUSE_ETH_DST_ADDR};
static uint8_t g_vlan_hdr[VLAN_HLEN] = {VLAN_HDR};
static uint8_t g_dst_ip[4] = {DST_IP};
static uint8_t g_src_ip[4] = {SRC_IP};
static uint16_t g_send_seq = 0;

void create_data_packet(void *buf);
void create_send_work_request(struct ibv_send_wr *, struct ibv_sge *, struct ibv_mr *, void *, uint64_t, enum Packet_type);
void create_recv_work_request(struct ibv_qp *, struct ibv_recv_wr *, struct ibv_sge *, struct ibv_mr *, void *, struct raw_eth_flow_attr *);
void *thread_fucntion(void *Thread_arg);
static uint16_t gen_ip_checksum(const char *buf, int num_bytes);
