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
	.symbol_name = "vxlan_xmit"
};


static int ip_show( struct sk_buff *skb, struct net_device *dev)
{
		int nhoff = skb_network_offset(skb);
		const struct iphdr *iph;
		struct iphdr _iph;
		__be16 src_port = 0;
		u32 hash;
		struct sock *sk = skb->sk;

		
		iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
		if (!iph)
			return -1;


		if (NULL != sk){	
		printk(KERN_INFO "\nshow src: %u.%u.%u.%u, dst: %u.%u.%u.%u; skb->hash %u, l4_hash %d, sw_hash %d sk->sk_txhash %u\n",
            		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), skb->hash, skb->l4_hash, skb->sw_hash, sk->sk_txhash);
		}else{
	
		printk(KERN_INFO "\nshow src: %u.%u.%u.%u, dst: %u.%u.%u.%u; skb->hash %u, l4_hash %d, sw_hash %d sk is null\n",
            		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), skb->hash, skb->l4_hash, skb->sw_hash);
		}


		//printk(KERN_INFO "\n\n src: %u.%u.%u.%u, dst: %u.%u.%u.%u\n", 
		//		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
	
		//printk(KERN_INFO "\nshow src: %u.%u.%u.%u, dst: %u.%u.%u.%u; skb->hash %u, l4_hash %d, sw_hash %d\n",
            	//	NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), skb->hash, skb->l4_hash, skb->sw_hash);
	
		//printk(KERN_INFO "\n skb->hash set 0\n");
		//skb->hash = 0;

		
		//printk(KERN_INFO "pre skb_get_hash l4_hash %d, sw_hash %d\n", skb->l4_hash, skb->sw_hash);
		//skb->l4_hash = 0;
		//skb->sw_hash = 0;
		//skb->hash = 0;		

		//hash = skb_get_hash(skb);
	

		src_port = udp_flow_src_port(dev_net(dev), skb, 0,
				     0, true);

		printk(KERN_INFO "post udp_flow_src_port src port %hu, kb->hash %u, l4_hash %d, sw_hash %d\n", 
						 ntohs(src_port), skb->hash, skb->l4_hash, skb->sw_hash);
		//printk(KERN_INFO "src port %hu\n", ntohs(src_port));

		return 0;
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	printk(KERN_INFO "\n ------------start----------------------\n");
	
	printk(KERN_INFO "vxlan pre_handler : p->addr = 0x%p, ip = %lx,",
	" flags = 0x%lx\n", p->addr, regs->ip, regs->flags);

	struct sk_buff *sk;
	sk = regs->di;	
	struct net_device *dev = regs->si;

	  printk(KERN_INFO "%s name:%s pid:%d, sk %p\n\n",
            p->symbol_name, current->comm, task_pid_nr(current), sk);
	
	dump_stack();

	ip_show(sk, dev);	

	printk(KERN_INFO "\n ------------end----------------------\n");

	return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs,
			unsigned long flags)
{
	printk(KERN_INFO "post_handler : p->addr = 0x%p, flags = 0x%lx\n",
		p->addr, regs->flags);

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


