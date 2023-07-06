#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <asm/ptrace.h>
#include <net/udp.h>
#include <linux/netdevice.h>


#include "ixgbe.h"
#include "ixgbe_common.h"
#include "ixgbe_dcb_82599.h"
#include "ixgbe_phy.h"
#include "ixgbe_sriov.h"
#include "ixgbe_model.h"
#include "ixgbe_txrx_common.h"


#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

#define IXGBE_RSS_L4_TYPES_MASK \
        ((1ul << IXGBE_RXDADV_RSSTYPE_IPV4_TCP) | \
         (1ul << IXGBE_RXDADV_RSSTYPE_IPV4_UDP) | \
         (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_TCP) | \
         (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_UDP))


static struct kprobe kp = {
	.symbol_name = "ixgbe_process_skb_fields",
};


static int ip_filter(struct sk_buff *skb)
{
	int nhoff = skb_network_offset(skb);
        const struct iphdr *iph;
        struct iphdr _iph;

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
        if (!iph)
              return 0;

	printk(KERN_INFO, "ip saddr %x\n", iph->saddr);
	if (iph->saddr == 0x1030303){
		return 1;
	}

	return 0;
}


static int ip_show( struct sk_buff *skb)
{
		int nhoff = skb_network_offset(skb);
		const struct iphdr *iph;
		struct iphdr _iph;
		__be16 src_port = 0;
		u32 hash;

		iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
		if (!iph)
			return -1;

		printk(KERN_INFO "\n\n src: %u.%u.%u.%u, dst: %u.%u.%u.%u\n", 
				NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
	
		printk(KERN_INFO "\nshow saddr : %x, daddr %x, hash %u\n",
            		iph->saddr, iph->daddr, skb->hash);
	
		//printk(KERN_INFO "\n skb->hash set 0\n");
		//skb->hash = 0;

		
		printk(KERN_INFO "ixgbe_rx_hash after show : hash %u, l4_hash %d, sw_hash %d\n", skb->hash, skb->l4_hash, skb->sw_hash);
		skb->l4_hash = 0;
		skb->sw_hash = 0;
		skb->hash = 0;		

		hash = skb_get_hash(skb);
		printk(KERN_INFO "post skb_get_hash %u, l4_hash %d, sw_hash %d\n", hash, skb->l4_hash, skb->sw_hash);
	
		//src_port = udp_flow_src_port(dev_net(dev), skb, 0,
		//		     0, true);

		//printk(KERN_INFO "src port %hu\n", ntohs(src_port));

		return 0;
}

static inline void ixgbe_rx_hash(struct ixgbe_ring *ring,
                                 union ixgbe_adv_rx_desc *rx_desc,
                                 struct sk_buff *skb)
{
        u16 rss_type;

        if (!(ring->netdev->features & NETIF_F_RXHASH))
                return;

        rss_type = le16_to_cpu(rx_desc->wb.lower.lo_dword.hs_rss.pkt_info) &
                   IXGBE_RXDADV_RSSTYPE_MASK;

        if (!rss_type)
                return;

        skb_set_hash(skb, le32_to_cpu(rx_desc->wb.lower.hi_dword.rss),
                     (IXGBE_RSS_L4_TYPES_MASK & (1ul << rss_type)) ?
                     PKT_HASH_TYPE_L4 : PKT_HASH_TYPE_L3);
}


static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	//printk(KERN_INFO "vxlan pre_handler : p->addr = 0x%p, ip = %lx,",
	//" flags = 0x%lx\n", p->addr, regs->ip, regs->flags);


	struct sk_buff *sk;
	sk = regs->dx;	
	struct ixgbe_ring *ring = regs->di;
	struct net_device *dev = ring->netdev;

	//if (0 == ip_filter(sk)){
	//	return 0;
	//}

	  printk(KERN_INFO "%s name:%s pid:%d, sk %p\n\n",
            p->symbol_name, current->comm, task_pid_nr(current), sk);
	
	//dump_stack();

	
	if (!(ring->netdev->features & NETIF_F_RXHASH)){
		printk(KERN_INFO "return rx dev %s\n", dev->name);
		return 0;
	}else {

		printk(KERN_INFO "not return rx dev %s\n", dev->name);
	}

	printk(KERN_INFO "handler pre : before show : hash %u, l4_hash %d, sw_hash %d\n", sk->hash, sk->l4_hash, sk->sw_hash);
	//skb_clear_hash(sk);
	ixgbe_rx_hash(regs->di, regs->si, sk);

	printk(KERN_INFO "handler pre : after show : hash %u, l4_hash %d, sw_hash %d\n", sk->hash, sk->l4_hash, sk->sw_hash);

	//ip_show(sk);	

	return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs,
			unsigned long flags)
{
	//printk(KERN_INFO "post_handler : p->addr = 0x%p, flags = 0x%lx\n",
		//p->addr, regs->flags);

	return ;
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO "fault_handler : p->addr = 0x%p, trap #%d\n",
	p->addr, trapnr);

	return 0;
}

static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;

	ret = register_kprobe(&kp);
	if (ret < 0){
		printk(KERN_INFO "register kprobe failed %d\n", ret);
		return ret;
	}

	printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
	return 0;
}


static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	printk(KERN_INFO "kprobe at %p unregister\n", kp.addr);
	return ;
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");


