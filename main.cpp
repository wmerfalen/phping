#include <phpcpp.h>
#include <iostream>
#include <string>
#include <pcap/pcap.h>
#include <libnet.h>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
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

pcap_t* pcap_handle = nullptr;
libnet_t *libnet = nullptr;

int send_ping(std::string srcIp,std::string dstIp,std::string device);
std::string get_device_ip(std::string device);
int ping_host(std::string host,std::string dev,Php::Value callback,Php::Value count);
bool is_reply(std::string src_ip,struct pcap_pkthdr *,const u_char*);

void ping(Php::Parameters &params){
    int ret = 0;
    if(params.size() == 3){
        ret = ping_host(params[0],params[1],params[2],3);
    }
    if(params.size() == 4){
        ret = ping_host(params[0],params[1],params[2],params[3]);
    }
    if(ret < 0){
        //Throw exception?
        //
    }

}


/**
 *  tell the compiler that the get_module is a pure C function
 */
extern "C" {
    
    /**
     *  Function that is called by PHP right after the PHP process
     *  has started, and that returns an address of an internal PHP
     *  strucure with all the details and features of your extension
     *
     *  @return void*   a pointer to an address that is understood by PHP
     */
    PHPCPP_EXPORT void *get_module() 
    {
        static Php::Extension extension("phping", "1.0");
        extension.add<ping>("ping",{
            Php::ByVal("host",Php::Type::String,true),
            Php::ByVal("device",Php::Type::String,true),
            Php::ByVal("callback",Php::Type::String,true),
            Php::ByVal("count",Php::Type::Numeric,false)
        });
        return extension;
    }
}

std::string get_device_ip(std::string device){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;

    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, (char*)device.substr(0,5).c_str(), IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    /* display result */
    std::string ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    return ip;
}


int ping_host(std::string host,std::string dev,Php::Value callback,Php::Value count = 3){
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
    std::string filter_exp = "icmp";
    int ret;
    struct pcap_pkthdr pkt_hdr;

    if(dev.length() == 0){
        return -1;
    }

    std::string src_ip = get_device_ip(dev);
    std::string dst_ip = host;

    if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    pcap_handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 10, errbuf);
    if (pcap_handle == NULL) {
        return -2;
    }
    if (pcap_compile(pcap_handle, &fp, filter_exp.c_str(), 0, net) == -1) {
        return -3;
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        return -4;
    }

    pcap_set_immediate_mode(pcap_handle,11);
    int ctr = count;
    /* Grab a packet */
    while(ctr-- > 0){
        send_ping(src_ip,dst_ip,dev);
        const u_char* packet = pcap_next(pcap_handle,&pkt_hdr);
        packet = pcap_next(pcap_handle,&pkt_hdr);
        if(packet){
            if(is_reply(dst_ip,&pkt_hdr,packet)){
                callback();
            }
        }
        sleep(1);
    }

    if(pcap_handle){
        pcap_close(pcap_handle);
    }
    return 0;
}

bool is_reply(std::string src_ip,struct pcap_pkthdr* pkt_hdr,const u_char* packet){
    struct ip_hdr * ptr_ip;
    struct icmp_hdr * ptr_icmp;	
    u_int size_ip;
    std::string pkt_src_ip;

    ptr_ip = (struct ip_hdr*)(packet + sizeof(struct eth_hdr));
    size_ip = IP_HL(ptr_ip)*4;
    if (size_ip < 20) {
        std::cerr << "Invalid IP header length\n";
        return false;
    }
    ptr_icmp = (struct icmp_hdr*)(packet + sizeof(struct eth_hdr)+ size_ip);
    pkt_src_ip = inet_ntoa(ptr_ip->ip_src);
    if(pkt_src_ip == src_ip && ptr_icmp->type == ICMP_ECHO_REPLY){
        return true;
    }
    return false;
}

int send_ping(std::string srcIp,std::string dstIp,std::string device){
    u_long src_ip = 0, dst_ip = 0;
    int  c,return_value = 0;
    libnet_ptag_t t;
  
    char errbuf[LIBNET_ERRBUF_SIZE];

    /*
     *  Fill the context queue with "count" packets, each with their own
     *  context.
     */
    device = device.substr(0,5);
    libnet = libnet_init(
            LIBNET_RAW4,                  /* injection type */
            device.c_str(),               /* network interface */
            errbuf);                      /* errbuf */

    if (libnet == NULL) {
        return -2;
    }
    /*
     *  Since we need a libnet context for address resolution it is
     *  necessary to put this inside the loop.
     */
    if (!dst_ip && (dst_ip = libnet_name2addr4(libnet, (char*)dstIp.c_str(), LIBNET_RESOLVE)) == -1){
        return -3;
    }
    if (!src_ip && (src_ip = libnet_name2addr4(libnet, (char*)srcIp.c_str(), LIBNET_RESOLVE)) == -1){
        return -4;
    }

    t = libnet_build_icmpv4_echo(
        ICMP_ECHO,                            /* type */
        0,                                    /* code */
        0,                                    /* checksum */
        0x42,                                 /* id */
        0x42,                                 /* sequence number */
        NULL,                                 /* payload */
        0,                                    /* payload size */
        libnet,                               /* libnet handle */
        0);
    if (t == -1){
        return_value = -5;
        goto bad;
    }
    t = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H, /* length */
        0,                                    /* TOS */
        0x42,                                 /* IP ID */
        0,                                    /* IP Frag */
        64,                                   /* TTL */
        IPPROTO_ICMP,                         /* protocol */
        0,                                    /* checksum */
        src_ip,                               /* source IP */
        dst_ip,                               /* destination IP */
        nullptr,                              /* payload */
        0,                                    /* payload size */
        libnet,                               /* libnet handle */
        0);
    if (t == -1){
        return_value = -6;
        goto bad;
    }
    c = libnet_write(libnet);
    if (c == -1){
        return_value = -7;
        goto bad;
    }
    libnet_destroy(libnet);
    libnet = nullptr;
    return 0;
bad:
    libnet_destroy(libnet);
    libnet = nullptr;
    return return_value;
}

