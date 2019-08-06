#include <linux/if_ether.h>

#define VLAN_HLEN 4      /* The additional bytes required by VLAN \ \
                          * (in addition to the Ethernet header)  \ \
                          */
#define VLAN_ETH_HLEN 18 /* Total octets in header.       */
#define VLAN_ETH_ZLEN 64 /* Min. octets in frame sans FCS */

/*
 * According to 802.3ac, the packet can be 4 bytes longer. --Klika Jan
 */
#define VLAN_ETH_DATA_LEN 1500  /* Max. octets in payload        */
#define VLAN_ETH_FRAME_LEN 1518 /* Max. octets in frame sans FCS */ 

/*
 *      struct vlan_hdr - vlan header
 *      @h_vlan_TCI: priority and VLAN ID
 *      @h_vlan_encapsulated_proto: packet type ID or len
 */

struct arphdr {
        __be16          ar_hrd;         /* format of hardware address   */
        __be16          ar_pro;         /* format of protocol address   */
        unsigned char   ar_hln;         /* length of hardware address   */
        unsigned char   ar_pln;         /* length of protocol address   */
        __be16          ar_op;          /* ARP opcode (command)         */


         /*
          *      Ethernet looks like this : This bit is variable sized however...
          */
        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[4];              /* sender IP address            */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[4];              /* target IP address            */
};

struct vlan_hdr
{
        __be16 h_vlan_TCI;
        __be16 h_vlan_encapsulated_proto;
};

struct lcchdr
{
        __extension__ union {
                struct
                {
                        u_int16_t lcc_sport; /* source port */
                        u_int16_t lcc_dport; /* destination port */
                        u_int16_t lcc_ulen;  /* length */
                        u_int16_t lcc_sum;   /* checksum */
                };
                struct
                {
                        u_int16_t source;
                        u_int16_t dest;
                        u_int16_t len;
                        u_int16_t check;
                };
        };
        u_int16_t ackReq : 1, /* is ACK request? */
            ack : 1,          /* is ACK? */
            data : 1,         /* is DATA? */
            reserve : 13;
        u_int16_t seq;
};

struct puase
{
        struct ethhdr eth;
        u_int16_t type;
        u_int16_t duration;
};
