#ifndef __PHPING_PING_HEADER__
#define __PHPING_PING_HEADER__ 1

#include <phpcpp.h>
#include <iostream>
#include <string>
#include <pcap/pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6
/* Ethernet header */
struct eth_hdr {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_hdr {
	u_char ip_vhl;      /* version << 4 | header length >> 2 */
	u_char ip_tos;      /* type of service */
	u_short ip_len;     /* total length */
	u_short ip_id;      /* identification */
	u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
	u_char ip_ttl;      /* time to live */
	u_char ip_p;        /* protocol */
	u_short ip_sum;     /* checksum */
	struct in_addr ip_src;
	struct in_addr ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)


#define ICMP_ECHO_REPLY      0
struct icmp_hdr{
    u_int8_t type;		        /* message type */
    u_int8_t code;		        /* type sub-code */
    u_int16_t checksum;
    union{
        struct{
            u_int16_t	id;
            u_int16_t	sequence;
        }echo;			        /* echo datagram */
        u_int32_t gateway;      /* gateway address */
        struct{
            u_int16_t	__unused;
            u_int16_t	mtu;
        }frag;			        /* path mtu discovery */
    }un;
};

typedef struct _response {\
    u_int16_t seq;\
    u_int16_t ms;\
} response;


class Phping : public Php::Base{
    private: 
        std::string m_host;
        std::string m_src_ip;
        std::string m_dest_ip;
        int         m_seq;
        std::vector<response> m_responses;
        std::string m_dev;
        int m_avg_response;
        int m_max_responses;    
        libnet_t*           m_libnet;
        pcap_t*             m_pcap_handle;
        void                m_calculateAverageResponseTime();
        std::string         m_getDeviceIp(std::string dev);
        int                 m_ping(std::string,int,Php::Value);
        int                 m_sendPacket(u_int16_t);
        std::string         m_error_string;
    public:
        Phping() = default;
        virtual ~Phping() = default;
        Php::Value          getHost() const { return m_host; }
        Php::Value          getDestIp() const { return m_dest_ip; }
        Php::Value          getAvg() const { return m_avg_response; }
        Php::Value          getErrorStr() const { return m_error_string; }
        void                setMaxResponses(Php::Parameters &m){ m_max_responses = m[0]; }
        void                setDevice(Php::Parameters& dev){ m_dev = (const char*)dev[0]; }
        void                setSequenceNumber(Php::Parameters& s){ m_seq = s[0]; }
        Php::Value          getSequenceNumber() const { return m_seq; }
        Php::Value          ping(Php::Parameters &params);
};

bool is_reply(std::string src_ip,struct pcap_pkthdr* pkt_hdr,const u_char* packet,u_int16_t sequence_number);

#endif
