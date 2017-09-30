#include <ctype.h>  
#include <errno.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include<math.h>
#include <netinet/tcp.h>

#define ETHER_ADDR_LEN 6
struct sniff_ethernet { 
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */ 
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */ 
	u_short ether_type; /* IP? ARP? RARP? etc */ 
}; 

struct sniff_ip {
	u_char ip_vhl; 
	u_char ip_tos; /* type of service */ 
	u_short ip_len; /* total length */ 
	u_short ip_id; /* identification */ 
	u_short ip_off; /* fragment offset field */ 
	#define IP_RF 0x8000 /* reserved fragment flag */ 
	#define IP_DF 0x4000 /* dont fragment flag */
	#define IP_MF 0x2000 /* more fragments flag */ 
	#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
	u_char ip_ttl; /* time to live */ 
	u_char ip_p; /* protocol */ 
	u_short ip_sum; /* checksum */ 
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
/* 
struct in_addr {

    in_addr_t s_addr;
    //call "inet_ntoa()" covert it to char*
};
*/
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4) 


struct sniff_tcp { 
	u_short th_sport; /* source port */ 
	u_short th_dport; /* destination port */ 
	tcp_seq th_seq; /* sequence number */
	tcp_seq th_ack; /* acknowledgement number */
	u_char th_offx2; /* data offset, rsvd */
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4) 
	u_char th_flags; 
	#define TH_FIN 0x01 
	#define TH_SYN 0x02 
	#define TH_RST 0x04 
	#define TH_PUSH 0x08 
	#define TH_ACK 0x10
	#define TH_URG 0x20 
	#define TH_ECE 0x40 
	#define TH_CWR 0x80 
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR) 
	u_short th_win; /* window */ 
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
}; 

const char *th_flags[]={"FIN","SYN","RST","PUSH","ACK","URG","ECE","CWR"};

/* ICMP header */
struct sniff_icmp {
	u_char icmp_type;
	#define ICMP_ECHO 0x8
	#define ICMP_REPLY 0x0
	u_char icmp_code;
	u_short icmp_sum;
	u_short icmp_id;
	u_short icmp_sequence;
};


struct sniff_udp {  
	u_short udp_sport;  
	u_short udp_dport;  
	u_short udp_len;  
	u_short udp_sum;  
}; 

u_short con_iphdlen(const u_char *p){
	u_short num = 0;
	u_short temp = *p;
	for(int i=0;i<4;i++){
		if((temp&1)==1)
			num+=pow(2,i);
		temp=temp>>1;
	}
	return num;
};
