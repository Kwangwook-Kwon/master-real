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
#define DATA_PACKET_SIZE 1000 
#define ACK_PACKET_SIZE 60

#define TOTAL_TRANSMIT_DATA -1
#define SEND_BUCKET_LIMIT 33000
#define SENT_QUEUE_LENGTH 100000
#define ACK_QUEUE_LENGTH 50000
#define DATA_QUEUE_LENGTH 100000

/* template of packet to send */
#define PAUSE_ETH_DST_ADDR 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01
#define BRD_MAC 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
 

#define UDP_SRC 12357
#define UDP_DST_DCQCN 0xB712
#define UDP_DST 0xB711


#define INPUT_CDF_FILE "workload/workload_search.tcl"

#define MAX(a,b)\
({ __typeof__ (a) _a = (a);\
__typeof__ (b) _b = (b); \
_a > _b ? _a : _b; })
  
#define MIN(a,b)\
({ __typeof__ (a) _a = (a); \
__typeof__ (b) _b = (b); \
_a < _b ? _a : _b; })

enum Thread_action
{
    SENDING_AND_RECEVING,
    SENDING_ONLY,
    RECEIVING_ONLY
};

enum CC_mode
{
    LCC,
    TIMELY,
    DCQCN,
    STREAM,
    RECV
};

enum Flow_mode
{
    INFINITE,
    DYNAMIC,
    ONCE
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

struct Sent_queue
{
    bool endofdata;
    long sent_time_app;
    uint32_t sent_time_hw;
    uint32_t seq;
};


struct Data_queue
{   
    void *buf;
    int wr_id;
};

struct Data_allow_queue
{
    int wr_id;
};

struct raw_eth_flow_attr
{
    struct ibv_flow_attr attr;
    struct ibv_flow_spec_eth spec_eth;
};

uint64_t buf_size_send = ENTRY_SIZE * DATA_QUEUE_LENGTH; /* maximum size of data to be access directly by hw */
uint64_t buf_size_recv = ENTRY_SIZE * RQ_NUM_DESC; /* maximum size of data to be access directly by hw */


static uint8_t g_dst_mac_addr[ETH_ALEN];// = {DST_MAC};
static uint8_t g_src_mac_addr[ETH_ALEN];// = {SRC_MAC};
static uint8_t g_recv_mac_addr[ETH_ALEN];// = {SRC_MAC};
static uint8_t g_brd_mac_addr[ETH_ALEN] = {BRD_MAC};
static uint8_t g_eth_pause_addr[ETH_ALEN] = {PAUSE_ETH_DST_ADDR};
static uint8_t g_dst_ip[4];// = {DST_IP};
static uint8_t g_src_ip[4];// = {SRC_IP};
static uint8_t g_recv_ip[4];
static uint16_t g_vlan_hdr_data;
static uint16_t g_vlan_hdr_ack;///[VLAN_HLEN] = {VLAN_HDR};
static uint32_t g_send_seq = 0;
static uint32_t g_flow_id = 0;
static uint32_t g_fct;
static uint32_t g_rtt_hw;
static uint64_t g_flow_size = 0;
static uint64_t g_flow_rem = 10000000;
static uint64_t g_total_send = 0;
static uint64_t g_total_recv = 0;
static double g_init_rate;
static double g_send_rate;
static double g_prev_rate;
static double g_recv_rate = 0;
static long g_rtt_app;
static long g_time;
static long g_time_require;
static long g_flow_start;
static int sent_queue_head = 0;
static int sent_queue_tail = 0;
static int ack_queue_head = 0;
static int ack_queue_tail = 0;
static int data_queue_head = 0;
static int data_queue_tail = 0;
static int data_allow_queue_head = 0;
static int data_allow_queue_tail = 0;
static int g_seed = 0;
static int g_ack_req_inv = 16;
static int g_process =1;
static int g_num_flows = 0;
static short g_vlan_id;
static bool g_lcc_mode = true;
static bool g_flow_active;
static struct Sent_queue sent_queue[SENT_QUEUE_LENGTH];
static struct Data_queue ack_queue[ACK_QUEUE_LENGTH];
static struct Data_queue data_queue[DATA_QUEUE_LENGTH];
static struct Data_allow_queue data_allow_queue[DATA_QUEUE_LENGTH];
static void *buf_send;
static double g_rate_diff_grad;
static double g_rate_diff;
static double g_normalize_gradient;
static enum CC_mode g_cc_mode;
static enum Flow_mode g_flow_mode;


double dcqcn_rate_target = 9.8;
double dcqcn_alpha = 1;
double dcqcn_g = 1.0 / 256.0;
int dcqcn_T, dcqcn_BC = 0;
long dcqcn_time_prev= 0;
uint64_t dcqcn_seq_prev = 0;


pthread_mutex_t mutex_dcqcn;


pthread_mutex_t mutex_sender_thread;
pthread_mutex_t mutex_flow_complete_flag;


void create_data_packet(void *buf, bool ack);
void create_ack_packet(void *buf, uint32_t seq, uint32_t ack_time, uint8_t *client_ip);
void create_send_work_request(struct ibv_send_wr *, struct ibv_sge *, struct ibv_mr *, void *, uint64_t, enum Packet_type);
void create_recv_work_request(struct ibv_qp *, struct ibv_recv_wr *, struct ibv_sge *, struct ibv_mr *, void *, struct raw_eth_flow_attr *);
void *send_data(void *Thread_arg);
void *recv_ack(void *Thread_arg);
void *recv_data(void *thread_arg);
void *send_data(void *thread_arg);
void *clock_thread_function();
double find_median(double *rate_array, int arry_p);
void swap(double *a, double *b);
void quicksort(int left, int right, double *data);
static uint16_t gen_ip_checksum(const char *buf, int num_bytes);
