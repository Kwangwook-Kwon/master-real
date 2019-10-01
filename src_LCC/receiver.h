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
#define ENTRY_SIZE 1100  /* maximum size of each send buffer */
#define SQ_NUM_DESC 9081/* maximum number of sends waiting for completion */
#define RQ_NUM_DESC 9081
#define NUM_SEND_THREAD 1
#define DATA_PACKET_SIZE 1500
#define ACK_PACKET_SIZE 60
#define TOTAL_TRANSMIT_DATA -1
#define ACK_QUEUE_LENGTH 2048

/* template of packet to send */
#define DST_MAC_RECV 0x50, 0x6b, 0x4b, 0x11, 0x11, 0x22
#define SRC_MAC 0x50, 0x6b, 0x4b, 0x11, 0x11, 0x22
#define DST_MAC 0x24, 0x8a, 0x07, 0xcb, 0x48, 0x08
#define PAUSE_ETH_DST_ADDR 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01
#define ETH_TYPE_VLAN 0x81, 0x00
#define VLAN_HDR 0x00, 0x0a
#define ETH_TYPE 0x08, 0x00

#define DST_IP 0x0a, 0x00, 0x09, 0x03
#define SRC_IP 0x0a, 0x00, 0x0a, 0x03


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
    ACK,
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

struct ack_queue_items{
    uint32_t seq;
    uint32_t ack_time;
    uint8_t client_ip[4];
    uint8_t tos;
    bool endofdata;
};

uint64_t buf_size_send = ENTRY_SIZE * SQ_NUM_DESC; /* maximum size of data to be access directly by hw */
uint64_t buf_size_recv = ENTRY_SIZE * RQ_NUM_DESC; /* maximum size of data to be access directly by hw */

static uint8_t g_dst_mac_addr[ETH_ALEN];// = {DST_MAC};
static uint8_t g_src_mac_addr[ETH_ALEN];// = {SRC_MAC};
static uint8_t g_recv_mac_addr[ETH_ALEN];
static uint8_t g_brd_mac_addr[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t g_eth_pause_addr[ETH_ALEN] = {PAUSE_ETH_DST_ADDR};
static uint16_t g_vlan_hdr_ack;///[VLAN_HLEN] = {VLAN_HDR};
static uint8_t g_dst_ip[4];// = {DST_IP};
static uint8_t g_src_ip[4];// = {SRC_IP};
static uint8_t g_recv_ip[4];
static uint32_t g_recv_seq = 0;
static uint64_t g_total_recv = 0;
static int g_seq_revert = 0;
static long g_time;
static short g_vlan_id;
static int ack_queue_head = 0, ack_queue_tail = 0;
static struct ack_queue_items ack_queue[ACK_QUEUE_LENGTH];

pthread_mutex_t mutex_ack_queue;
pthread_mutex_t mutex_g_recv_data;


void create_data_packet(void *buf);
void create_ack_packet(void *buf, uint32_t seq, uint32_t ack_time, uint8_t *client_ip, bool endofdata);
void create_send_work_request(struct ibv_send_wr *, struct ibv_sge *, struct ibv_mr *, void *, uint64_t, enum Packet_type);
void create_recv_work_request(struct ibv_qp *, struct ibv_recv_wr *, struct ibv_sge *, struct ibv_mr *, void *, struct raw_eth_flow_attr *);
void *clock_thread_function();
void *recv_thread_function(void *Thread_arg);
static uint16_t gen_ip_checksum(const char *buf, int num_bytes);

