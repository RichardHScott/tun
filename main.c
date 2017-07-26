#include <fcntl.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>

int tun_alloc(char *dev);
ssize_t tun_read(int fd, char *buffer, size_t len);
ssize_t tun_write(int fd, char *buffer, size_t len);

struct netdev {
    uint32_t addr;
    uint32_t addr_len;
    uint8_t hwaddr[6];
    uint32_t mtu;
};

struct eth_hdr {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ethertype;
    uint8_t payload[];
} __attribute__((packed));

struct arp_hdr {
    uint16_t hwtype;
    uint16_t prototype;
    uint8_t hwlen;
    uint8_t protolen;
    uint16_t op;
    uint8_t payload[];
} __attribute__((packed));

struct arp_ipv4 {
    uint8_t smac[6];
    uint32_t src_ip;
    uint8_t dmac[6];
    uint32_t dest_ip;
} __attribute__((packed));

int handle_frame(struct eth_hdr *frame);

static int set_if_route(char *dev, char *cidr);
static int set_if_address(char *dev, char *cidr);
static int set_if_up(char *dev);

static int run_cmd(char *command, ...);

static const size_t BUFLEN = 2048;

static struct eth_hdr* eth_hdr(struct ethhdr *hdr) {
    struct eth_hdr* eth_hdr = (struct eth_hdr*) hdr;
    eth_hdr->ethertype = ntohs(eth_hdr->ethertype);
    return eth_hdr;
};


struct translation_entry {
    uint16_t prototype;
    uint8_t mac[6];
    uint32_t ip;
};

const size_t TRANS_TABLE_LENGTH;
int last_entry = 0;
struct translation_entry *translation_table;

char my_mac[6] = {0x00, 0x0d, 0x69, 0x9d, 0x52, 0x35};

int main(int argc, char **argv) {
	char tun_name[] = "dave";
	int fd = tun_alloc(tun_name);
	
	if(fd < 0) {
        perror("Error creating fd\n");
        exit(1);
    }

    printf("We have fd %d", fd);

    char tun_route[] = "10.0.0.0/24";
    char tun_address[] = "10.0.0.5";

    if(set_if_up(tun_name) != 0) {
        exit(1);
    }

    if(set_if_route(tun_name, tun_route) != 0) {
        exit(1);
    }

    if(set_if_address(tun_name, tun_address) != 0) {
        exit(1);
    }

    //The route has now been added.
    //struct netdev *loop = netdev_alloc("127.0.0.1", "00:00:00:00:00:00", 1500);
    //struct netdev *netdev = netdev_alloc("10.0.0.5", "00:0d:69:9d:52:35", 1500);

    translation_table = malloc(sizeof(struct translation_entry) * TRANS_TABLE_LENGTH);

    char buf[BUFLEN];
    memset(buf, 0, BUFLEN);

    while(tun_read(fd, buf, BUFLEN)) {
        struct ethhdr *ethhdr = (struct ethhdr*) buf;
        struct eth_hdr *hdr = eth_hdr(ethhdr);
        int status = handle_frame(hdr);

        if(status == 1) {
            tun_write(fd, buf, BUFLEN);
        }
    }

    close(fd);
	
	return 0; 
}

static struct netdev* netdev_alloc(char *addr, char *macaddr, uint32_t mtu) {
    struct netdev *dev = malloc(sizeof(struct netdev));
//    dev->addr = ip_parse(addr);
    dev->addr_len = 6;
    dev->mtu = mtu;

    sscanf(macaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
        &dev->hwaddr[0],
        &dev->hwaddr[1],
        &dev->hwaddr[2],
        &dev->hwaddr[3],
        &dev->hwaddr[4],
        &dev->hwaddr[5]);

    return dev;
}

static const size_t COMMAND_BUFLEN = 1024;

static int run_cmd(char *command, ...) {
    va_list arg_list;
    char buf[COMMAND_BUFLEN];
    va_start(arg_list, command);

    vsnprintf(buf, COMMAND_BUFLEN, command, arg_list);
    va_end(arg_list);
    
    return system(buf);
}

static int set_if_route(char *dev, char *cidr) {
    return run_cmd("ip route add dev %s %s", dev, cidr);
}

static int set_if_address(char *dev, char *cidr) {
    return run_cmd("ip address add dev %s local %s", dev, cidr); 
}

static int set_if_up(char *dev) {
    return run_cmd("ip link set dev %s up", dev); 
}

ssize_t tun_read(int fd, char* buffer, size_t len) {
    return read(fd, buffer, len);
}

ssize_t tun_write(int fd, char *buffer, size_t len) {
    return write(fd, buffer, len);
}

int get_proto_type(uint16_t type, char *buf, size_t buflen) {
    switch(type) {
       case ETH_P_IPV6:
        strncpy(buf, "IPv6", buflen);
        break;
       case ETH_P_IP:
        strncpy(buf, "IPv4", buflen);
        break;
       case ETH_P_ARP:
        strncpy(buf, "ARP", buflen);
        break;
       default:
        strncpy(buf, "Unknown", buflen);
   }

   return 0;
}

uint32_t parse_ip(char *ip) {
    uint32_t val;
    inet_pton(AF_INET, ip, &val);
    return val;
}

const int ARP_HANDLE_REPLY = 1;
const int ARP_HANDLE_DONE = 0;

const int ARP_OP_REQUEST = 1;
const int ARP_OP_REPLY = 2;

int handle_arp(struct arp_hdr* packet) {
    printf("Arp op %x\n", packet->op);
    printf("Arp proto %d\n", packet->prototype);
/*
    if(ntohs(packet->prototype) != 0x0800) {
        printf("Unsupported type");
        return 0;
    }
*/
    struct arp_ipv4* data = (struct arp_ipv4*) packet->payload;
    bool merge = false;

    //find in table
    for(size_t i=0; i < last_entry; i++) {
        if(translation_table[i].prototype != packet->prototype) {
            continue;
        }

        if(translation_table[i].ip == data->src_ip) {
            printf("Update mac\n");
            memcpy(translation_table[i].mac, data->smac, 6);
            merge = true;
            break;
        }
    }
    
    if(data->dest_ip == parse_ip("10.0.0.4")) {
        printf("Our arp!\n");
        if(!merge) {
            printf("New mac\n");
            memcpy(translation_table[last_entry].mac, data->smac, 6);
            translation_table[last_entry].ip = data->src_ip;
            translation_table[last_entry].prototype = packet->prototype;
            last_entry++;
        }

        if(packet->op == ARP_OP_REQUEST) {
            printf("Was arp request\n");
            data->dest_ip = data->src_ip; 
            data->src_ip = parse_ip("10.0.0.4");

            memcpy(data->dmac, data->smac, 6);
            memcpy(data->smac, my_mac, 6);

            packet->op = ARP_OP_REPLY;

            return ARP_HANDLE_REPLY;
        }
    } else {
        printf("Not our arp.\n");
    }

    return ARP_HANDLE_DONE;
}

struct arp_hdr* arp_hdr(struct arphdr *hdr) {
    struct arp_hdr *header = (struct arp_hdr*) hdr;

    header->hwtype = ntohs(header->hwtype);
    header->prototype = ntohs(header->prototype);
    header->op = ntohs(header->op);

    return header;
}

int handle_frame(struct eth_hdr *frame) {
    printf("Dest \t");
    for(size_t i=0; i < ETH_ALEN; ++i) printf("%hhx ", frame->dmac[i]);
    printf("\nSrc \t");
    for(size_t i=0; i < ETH_ALEN; ++i) printf("%hhx ", frame->smac[i]);
    char protobuf[16];
    get_proto_type(frame->ethertype, protobuf, 16);
    printf("\nType \t %x \t %s\n", frame->ethertype, protobuf);

    switch(frame->ethertype) {
        case ETH_P_ARP: {
            struct arp_hdr *header = arp_hdr((struct arphdr*) frame->payload); 
            int status = handle_arp(header);
            if(status == ARP_HANDLE_REPLY) {
                printf("Send reply\n");
                header->hwtype = htons(header->hwtype);
                header->prototype = htons(header->prototype);
                header->op = htons(header->op);

                frame->ethertype = htons(frame->ethertype);
                
                char tmp_mac[6];
                memcpy(tmp_mac, frame->dmac, 6);
                memcpy(frame->dmac, frame->smac, 6);
                memcpy(frame->smac, my_mac, 6);
                return 1;
            }
            }
            break;
    }

    return 0;
}

int tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("Cannot open TUN/TAP dev\n");
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if(*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if( (err = ioctl(fd, TUNSETIFF, (void*) &ifr)) < 0) {
		perror("Could not ioctl tun\n");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

/*
struct netdev* netdev_alloc(char *addr, char *hwaddr, uint32_t mtu) {
    struct netdev *dev = malloc(sizeof(struct netdev));
    dev->addr = ip_parse(addr);
    dev->hwaddr[] = 
    dev->addr_len = 6;
    dev->mtu = mtu;
*/
