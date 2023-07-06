#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <asm/ptrace.h>
#include <net/udp.h>
#include <linux/netdevice.h>

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

static struct kprobe kp = {
	//.symbol_name = "__skb_get_hash",
	.symbol_name = "ip_rcv"
};


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
	
		//printk(KERN_INFO "\nshow saddr : %x, daddr %x, hash %u\n",
            	//	iph->saddr, iph->daddr, skb->hash);
	
		//printk(KERN_INFO "\n skb->hash set 0\n");
		//skb->hash = 0;

		
		printk(KERN_INFO "ip show l4_hash %d, sw_hash %d, hash %d-----\n\n", skb->hash, skb->l4_hash, skb->sw_hash);
		//skb->l4_hash = 0;
		//skb->sw_hash = 0;
		//skb->hash = 0;		

		//hash = skb_get_hash(skb);
		//printk(KERN_INFO "post skb_get_hash %u, l4_hash %d, sw_hash %d\n", hash, skb->l4_hash, skb->sw_hash);
	

		//src_port = udp_flow_src_port(dev_net(dev), skb, 0,
		//		     0, true);

		//printk(KERN_INFO "src port %hu\n", ntohs(src_port));

		return 0;
}

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


static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{

	
	struct sk_buff *sk;
	sk = regs->di;	
	//struct net_device *dev = regs->si;
	const struct iphdr *iph;
	iph = ip_hdr(sk);
	if (NULL == iph){
		return 0;
	}

	printk(KERN_INFO "ip saddr %x show l4_hash %d, sw_hash %d, hash %u-----\n\n", iph->saddr, sk->l4_hash, sk->sw_hash, sk->hash);
	
	if (0 == ip_filter(sk)){
		return 0;
	}

	printk(KERN_INFO "-----ip pre_handler : p->addr = 0x%p, ip = %lx,",
	" flags = 0x%lx\n", p->addr, regs->ip, regs->flags);

	  printk(KERN_INFO "%s name:%s pid:%d, sk %p\n\n",
            p->symbol_name, current->comm, task_pid_nr(current), sk);
	
	//dump_stack();

	ip_show(sk);	

	return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs,
			unsigned long flags)
{
	//printk(KERN_INFO "post_handler : p->addr = 0x%p, flags = 0x%lx\n",
	//	p->addr, regs->flags);

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


