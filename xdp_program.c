#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#define Swap2Bytes(val) \
	( (((val) >> 8) & 0x00FF) | (((val) << 8) & 0xFF00) )

int xdpFilter(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	
	char msg[] = "New Packet\n";
	bpf_trace_printk(msg, sizeof(msg));
	
	struct iphdr *ip = data + sizeof(*eth);
		
	if ((void*)ip + sizeof(*ip) > data_end) {
		return XDP_PASS;
	}
			
	if (ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}
	
	struct tcphdr *tcp = (void*)ip + sizeof(*ip);
	
	if ((void*)tcp + sizeof(*tcp) > data_end) {
		return XDP_PASS;
	}
	
	int srcPort = Swap2Bytes(tcp->source);
	int dstPort = Swap2Bytes(tcp->dest);
	
	if (dstPort == 8000 || srcPort == 8000) {
		void* data = (void*)tcp + sizeof(*tcp);
		
		if (data >= data_end) {
			return XDP_PASS;
		}
		
		char msg[] = "TRAFFIC FROM %d TO %d\n";
		bpf_trace_printk(msg, sizeof(msg), srcPort, dstPort);
	}
	
	return XDP_PASS;
}
