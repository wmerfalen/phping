#include "ping.hpp"

Php::Value Phping::ping(Php::Parameters& params){
    //Host, device, callback, count, sequence number
    //====================================
    std::string host = params[0];
    Php::Value retVal = true;
    m_ping(host,params[3],params[2]);
    return retVal;
}

std::string Phping::m_getDeviceIp(std::string device){
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


int Phping::m_ping(std::string host,int count = 3,Php::Value callback = nullptr){
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
    std::string filter_exp = "icmp";
    struct pcap_pkthdr pkt_hdr;

    m_src_ip = m_getDeviceIp(m_dev);
    m_dest_ip = host;

    if (pcap_lookupnet(m_dev.c_str(), &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    m_pcap_handle = pcap_open_live(m_dev.c_str(), BUFSIZ, 1, 10, errbuf);
    if (m_pcap_handle == NULL) {
        return -2;
    }
    if (pcap_compile(m_pcap_handle, &fp, filter_exp.c_str(), 0, net) == -1) {
        return -3;
    }
    if (pcap_setfilter(m_pcap_handle, &fp) == -1) {
        return -4;
    }

    pcap_set_immediate_mode(m_pcap_handle,11);
    int ctr = count;
    int ret = 0;
    u_int16_t seq = m_seq;
    /* Grab a packet */
    while(ctr-- > 0){
        ret = m_sendPacket(seq);
        const u_char* packet = pcap_next(m_pcap_handle,&pkt_hdr);
        packet = pcap_next(m_pcap_handle,&pkt_hdr);
        if(packet){
            if(is_reply(m_dest_ip,&pkt_hdr,packet,seq)){
                if(callback){
                    callback();
                }
            }
        }
        seq++;
        sleep(1);
    }

    if(m_pcap_handle){
        pcap_close(m_pcap_handle);
    }
    return 0;
}

bool is_reply(std::string src_ip,struct pcap_pkthdr* pkt_hdr,const u_char* packet,u_int16_t sequence_number){
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
    if(pkt_src_ip == src_ip && ptr_icmp->type == ICMP_ECHO_REPLY && ntohs(ptr_icmp->un.echo.sequence) == sequence_number){
        return true;
    }
    return false;
}

int Phping::m_sendPacket(u_int16_t sequence_number){
    u_long src_ip = 0, dst_ip = 0;
    int  c,return_value = 0;
    libnet_ptag_t t;
  
    char errbuf[LIBNET_ERRBUF_SIZE];

    /*
     *  Fill the context queue with "count" packets, each with their own
     *  context.
     */
    m_libnet = libnet_init(
            LIBNET_RAW4,                  /* injection type */
            m_dev.c_str(),               /* network interface */
            errbuf);                      /* errbuf */

    if (m_libnet == NULL) {
        return -2;
    }
    /*
     *  Since we need a m_libnet context for address resolution it is
     *  necessary to put this inside the loop.
     */
    if (!dst_ip && (dst_ip = libnet_name2addr4(m_libnet, (char*)m_dest_ip.c_str(), LIBNET_RESOLVE)) == -1){
        return -3;
    }
    if (!src_ip && (src_ip = libnet_name2addr4(m_libnet, (char*)m_src_ip.c_str(), LIBNET_RESOLVE)) == -1){
        return -4;
    }

    t = libnet_build_icmpv4_echo(
        ICMP_ECHO,                            /* type */
        0,                                    /* code */
        0,                                    /* checksum */
        0x42,                                 /* id */
        sequence_number,                      /* sequence number */
        NULL,                                 /* payload */
        0,                                    /* payload size */
        m_libnet,                               /* libnet handle */
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
        m_libnet,                               /* libnet handle */
        0);
    if (t == -1){
        return_value = -6;
        goto bad;
    }
    c = libnet_write(m_libnet);
    if (c == -1){
        return_value = -7;
        goto bad;
    }
    libnet_destroy(m_libnet);
    m_libnet = nullptr;
    return 0;
bad:
    libnet_destroy(m_libnet);
    m_libnet = nullptr;
    return return_value;
}

