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
#define NUM_SEND_THREAD 1
#define SENDING_RATE_IN_GIGA 10
#define DATA_PACKET_SIZE 1500

/* template of packet to send */
#define DST_MAC 0x24, 0x8a, 0x07, 0xcb, 0x48, 0x08
#define SRC_MAC 0x50, 0x6b, 0x4b, 0x11, 0x11, 0x11

#define VLAN_HDR 0x60, 0x09 // Priority 3

#define SRC_IP 0x0a, 0x00, 0x09, 0x03
#define DST_IP 0x0a, 0x00, 0x0a, 0x03

#define UDP_SRC 12357
#define UDP_DST 12358

struct ibv_pd *pd;
struct ibv_device **dev_list;
struct ibv_device *ib_dev;
struct ibv_context *context;

int buf_size = ENTRY_SIZE * SQ_NUM_DESC; /* maximum size of data to be access directly by hw */

static uint8_t g_dst_mac_addr[ETH_ALEN] = {DST_MAC};
static uint8_t g_src_mac_addr[ETH_ALEN] = {SRC_MAC};
static uint8_t g_vlan_hdr[2] = {VLAN_HDR};
static uint8_t g_dst_ip[4] = {DST_IP};
static uint8_t g_src_ip[4] = {SRC_IP};


void create_data_packet(void *buf);
void *sending_fucntion(void *id);
static uint16_t gen_checksum(const char *buf, int num_bytes);
