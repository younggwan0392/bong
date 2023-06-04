#include <pcap.h>

#include <stdio.h>

#include <string.h>



#include <mariadb/my_global.h>

#include <mariadb/mysql.h>



#include <errno.h>

#include <stdlib.h>



#include <sys/types.h>

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>



#include <sys/time.h>

#include <time.h>

#include <math.h>



#include <netinet/ip.h>

#include <netinet/ip6.h>

#include <linux/tcp.h>

#include <netdb.h>

#include "sqlhd.h"



#define SIZE_ETHERNET 14

#define SUPPORT_OUTPUT



// global variables ...

//char if_bind_global[] = "enp0s3" ;

char if_bind_global[] = "lo";

//int if_bind_global_len = 6 ;

int if_bind_global_len = 2;



int sendraw_mode = 1;



//char *query_string = NULL;

char query_string[40960];



/* Ethernet addresses are 6 bytes */

#define ETHER_ADDR_LEN   6



/* Ethernet header */

struct sniff_ethernet {

    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */

    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */

    u_short ether_type; /* IP? ARP? RARP? etc */

};



/* IP header */

struct sniff_ip {

    u_char ip_vhl;      /* version << 4 | header length >> 2 */

    u_char ip_tos;      /* type of service */

    u_short ip_len;      /* total length */

    u_short ip_id;      /* identification */

    u_short ip_off;      /* fragment offset field */

#define IP_RF 0x8000      /* reserved fragment flag */

#define IP_DF 0x4000      /* don't fragment flag */

#define IP_MF 0x2000      /* more fragments flag */

#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */

    u_char ip_ttl;      /* time to live */

    u_char ip_p;      /* protocol */

    u_short ip_sum;      /* checksum */

    struct in_addr ip_src, ip_dst; /* source and dest address */

};

#define IP_HL(ip)      (((ip)->ip_vhl) & 0x0f)

#define IP_V(ip)      (((ip)->ip_vhl) >> 4)



/* TCP header */

typedef u_int tcp_seq;



struct sniff_tcp {

    u_short th_sport;   /* source port */

    u_short th_dport;   /* destination port */

    tcp_seq th_seq;      /* sequence number */

    tcp_seq th_ack;      /* acknowledgement number */

    u_char th_offx2;   /* data offset, rsvd */

#define TH_OFF(th)   (((th)->th_offx2 & 0xf0) >> 4)

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

    u_short th_win;      /* window */

    u_short th_sum;      /* checksum */

    u_short th_urp;      /* urgent pointer */

};



struct pseudohdr {

    u_int32_t   saddr;

    u_int32_t   daddr;

    u_int8_t    useless;

    u_int8_t    protocol;

    u_int16_t   tcplength;

};



int print_chars(char print_char, int nums);

void print_payload(const u_char* payload, int len);

void print_payload_right(const u_char* payload, int len);

void print_hex_ascii_line(const u_char* payload, int len, int offset);

void print_hex_ascii_line_right(const u_char* payload, int len, int offset);

unsigned short in_cksum(u_short* addr, int len);

int sendraw(u_char* pre_packet, int mode);

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);



int main(int argc, char* argv[])

{

	pcap_t* handle;         /* Session handle */    

	char* dev;         /* The device to sniff on */    

	char dev2[64] = "lo";    

	char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */    

	struct bpf_program fp;      /* The compiled filter */   

	char filter_exp[] = "tcp dst port 80";   /* The filter expression */   

	bpf_u_int32 mask;      /* Our netmask */   

	bpf_u_int32 net;      /* Our IP */   

	struct pcap_pkthdr header;   /* The header that pcap gives us */

	const u_char* packet;      /* The actual packet */

        

	int loop_cnt = 0;    

	int return_value = 0;

    

	char hostname[] = "root";   

	char passwd[] = "1234";

	char colname[] = "testdb";



    	dev = pcap_lookupdev(errbuf);

    	if (dev == NULL) {

        	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        	return(2);

    	}

    	dev = dev2;

    	//printf("찾은 장치: %s\n",dev);

    	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {

    		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);

    		net = 0;

        	mask = 0;

		}



    	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    	if (handle == NULL) {

    		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

			return(2);

    	}



    	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {

			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));

			return(2);

		}

    

    	if (pcap_setfilter(handle, &fp) == -1) {

			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));

			return(2);

		}

	printf("Packet capture started!!!\n");

	

	/*DB연동*/

	connect_mysql_ubuntu(hostname, passwd, colname);

	

	/*pcap_loop*/

    	//return_value = pcap_loop(handle, 20, got_packet, NULL);

    	return_value = pcap_loop(handle, 0, got_packet, NULL);

    	if(return_value == -1)		printf("pcap_loop() error!");

    	else					printf("pcap_loop() success!!!!");

    

    	/* And close the session */

    	pcap_close(handle);

    	

    	/*DB종료*/

    	end_mysql();



    	printf("Packet capture program finished.\n");

    	return(0);

}



void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {

    	const struct sniff_ethernet* ethernet; /* The ethernet header */

    	const struct sniff_ip* ip; /* The IP header */

    	const struct sniff_tcp* tcp; /* The TCP header */

    	const char* payload; /* Packet payload */



    	u_int size_ip;

    	u_int size_tcp;



    	ethernet = (struct sniff_ethernet*)(packet);

    	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    	size_ip = IP_HL(ip) * 4;

    	if (size_ip < 20) {

    		printf("   * Invalid IP header length: %u bytes\n", size_ip);

        	return;

    	}

    	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

    	size_tcp = TH_OFF(tcp) * 4;

    	if (size_tcp < 20) {

        	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);

        	return;

    	}

    	payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    	

    	if (strncmp(payload, "GET /", 5) != 0) return;

    

    	char ip_src_str[16];

    	char ip_dst_str[16];



    	struct sockaddr_in sa, sa2;



    	//&(sa.sin_addr)

    	memcpy((char*)&(sa.sin_addr), (char*)&(ip->ip_src), 4);

    	memcpy((char*)&(sa2.sin_addr), (char*)&(ip->ip_dst), 4);



    	// print ip src , dst address

    	inet_ntop(AF_INET, &(sa.sin_addr), ip_src_str, 16);

    	inet_ntop(AF_INET, &(sa2.sin_addr), ip_dst_str, 16);

    	printf("Source IP\t : %s \n", ip_src_str);

    	printf("Destination IP   : %s \n", ip_dst_str);



    	// print tcp source , destination port info.

    	printf("Source PORT \t : %d \n", ntohs(tcp->th_sport));

    	printf("Destination PORT : %d \n", ntohs(tcp->th_dport));



    	char* host_data = NULL;

    	char* host_data_end = NULL;

    	int host_data_len = 0;

    	char host_data_str[256] = { 0x00 };



    	host_data = strstr(payload, "Host: ");

    	if (host_data != NULL) {

        	host_data += 6;



      	host_data_end = strstr(host_data, "\r\n"); //strstr(char* str1, char* str2) 주소 반환

        	host_data_len = host_data_end - host_data;

        	strncpy(host_data_str, host_data, host_data_len);



        	//char *host_data = strstr(payload , "Host: ");

        	// print host_data string .

        	printf("HOST : %s \n", host_data_str);

    	}

    	else 	return;

    	/////////////////////////////////////////////////////////////////////////////////////////////

	char bowl[1024];

	char *search_domain[256];

	char *result_query[256];

	char message[100];

	int length;

	int i = 0;

	struct hostent* hnt;

	

	sprintf(bowl,"select * from warningTest where host_name = '%s'",host_data_str);

	if(connect_query_mysql(bowl)) printf("NOTICE: SELECT OK!\n");

	

	result_query_mysql(result_query);

	if(!strcmp(result_query[0],host_data_str)){

		sendraw(packet, sendraw_mode);

	}



    	// insert log to db

    	sprintf(query_string,

        	"insert into testip"

        	"( src_ip , des_ip , src_port ,des_port, host_name, date)"

        	"value "

        	"( '%s' , '%s' , %d , %d, '%s',now())",

        	ip_src_str, ip_dst_str, ntohs(tcp->th_sport),ntohs(tcp->th_dport), host_data_str);

        	

       //DB 쿼리 실행

    	connect_query_mysql(query_string);

}// end got_packet function .



unsigned short in_cksum(u_short* addr, int len)

{

	int sum = 0;

    	int nleft = len;

    	u_short* w = addr;

    	u_short answer = 0;

    	while (nleft > 1) {

		sum += *w++;

        	nleft -= 2;

    	}



    	if (nleft == 1) {

		*(u_char*)(&answer) = *(u_char*)w;

		sum += answer;

  	}



    	sum = (sum >> 16) + (sum & 0xffff);

    	sum += (sum >> 16);

    	answer = ~sum;

    	return(answer);

}// end in_cksum function .



int sendraw(u_char* pre_packet, int mode)

{

	const struct sniff_ethernet* ethernet;  //



    	u_char packet[1600];    

    	int raw_socket;

    	int on = 1, len;

    	struct iphdr* iphdr;

    	struct tcphdr* tcphdr;

    	struct in_addr source_address, dest_address;

    	struct sockaddr_in address;

    	struct pseudohdr* pseudo_header;

    	struct in_addr ip;

    	int port;

    	int pre_payload_size = 0;

    	u_char* payload = NULL;

    	int size_vlan = 0;

    	int size_vlan_apply = 0;

    	int size_payload = 0;

    	int post_payload_size = 0;

    	int sendto_result = 0;

    	int setsockopt_result = 0;

    	int prt_sendto_payload = 0;



    	int warning_page = 1;

    	int vlan_tag_disabled = 0;

    	

    	/*저장공간 malloc

    	int recv_socketsqlTest

;

    	char recv_packet[100], compare[100];

    	struct sockaddr_in target_addr;

    	struct hostent* target;

    	int loop1 = 0;

    	int loop2 = 0;

    	int rc = 0;

    	struct ifreq ifr ;

    	char* if_bind;

    	int if_bind_len = 0;

    	char* ipaddr_str_ptr;

    	int ret = 0;*/



#ifdef SUPPORT_OUTPUT

    	printf("\n[Raw Socket Sendto][Start]\n\n");



    	if (size_payload) {

		print_chars('\t', 6);

		printf("pre_packet whole(L2-packet-data) (%d bytes only):\n", 100);

		print_payload_right(pre_packet, 100);

    	}

#endif

       // raw socket 생성

       raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

       if (raw_socket < 0) {

		print_chars('\t', 6);

            	fprintf(stderr, "Error in socket() creation - %s\n", strerror(errno));

            	return -2;



        }

       setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, (char*)&on, sizeof(on)); //사용자가 직접 IP 헤더를 조작하게 해주는 옵션



       if (if_bind_global != NULL) {					//SO_BINDTODEVICE: 주어진 인터페이스에서만 패킷을 보내는 옵션

       	setsockopt_result = setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len);

            	if (setsockopt_result == -1) {

			print_chars('\t', 6);

                	fprintf(stderr, "ERROR: setsockopt() - %s\n", strerror(errno));

                	return -2;

		}

        }

        

	ethernet = (struct sniff_ethernet*)(pre_packet);

       if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00") {

#ifdef SUPPORT_OUTPUT

		printf("vlan packet\n");

#endif

		size_vlan = 4;

		memcpy(packet, pre_packet, size_vlan); // d:packet - 빈 곳 s: pre_packet - 받은 인자

        }

       else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00") {

		size_vlan = 0;

	}

	else 		fprintf(stderr, "NOTICE: ether_type diagnostics failed .......... \n");



	vlan_tag_disabled = 1; // 1로 초기화 하면 vlan 비활성화 

	if (vlan_tag_disabled == 1) {

		size_vlan_apply = 0;

		memset(packet, 0x00, 4);

	}

	else 		size_vlan_apply = size_vlan;

	

        // TCP, IP 헤더 초기화

	iphdr = (struct iphdr*)(packet + size_vlan_apply);

	memset(iphdr, 0, 20);

	tcphdr = (struct tcphdr*)(packet + size_vlan_apply + 20);

	memset(tcphdr, 0, 20);



	// src와 des의 '주소'를 바꿈

	source_address.s_addr =((struct iphdr*)(pre_packet + size_vlan + 14))->daddr;	// => des 주소가 들어가 있음

	dest_address.s_addr = ((struct iphdr*)(pre_packet + size_vlan + 14))->saddr;   // => src 주소가 들어가 있음

	iphdr->id = ((struct iphdr*)(pre_packet + size_vlan + 14))->id;

	int pre_tcp_header_size = 0;

	char pre_tcp_header_size_char = 0x0;

	pre_tcp_header_size = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->doff;

	pre_payload_size = ntohs(((struct iphdr*)(pre_packet + size_vlan + 14))->tot_len) - (20 + pre_tcp_header_size * 4);



	tcphdr->source = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->dest;      // src와 des의 '포트' 를 바꿈

	tcphdr->dest = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->source;      // for return response

	tcphdr->seq = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->ack_seq;

	tcphdr->ack_seq = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->seq + htonl(pre_payload_size - 20);

	tcphdr->window = ((struct tcphdr*)(pre_packet + size_vlan + 14 + 20))->window;



	tcphdr->doff = 5; //data offset

	tcphdr->ack = 1;

	tcphdr->psh = 1;

	tcphdr->fin = 1;

        

        // 가상 헤더 생성.

	pseudo_header = (struct pseudohdr*)((char*)tcphdr - sizeof(struct pseudohdr)); //=12

	pseudo_header->saddr = source_address.s_addr;

	pseudo_header->daddr = dest_address.s_addr;

	pseudo_header->useless = (u_int8_t)0;

	pseudo_header->protocol = IPPROTO_TCP;

	pseudo_header->tcplength = htons(sizeof(struct tcphdr) + post_payload_size);



#ifdef SUPPORT_OUTPUT

	strcpy((char*)packet + 40, "HAHAHAHAHOHOHOHO\x0");

#endif

	// choose output content

	warning_page = 5;

	if (warning_page == 5) {

		//write post_payload(redirecting data 2)

		post_payload_size = 300 + 65;   // Content-Length: header is changed so post_payload_size is increased.

		memcpy((char*)packet + 40, "HTTP/1.1 200 OK\x0d\x0a"

		"Content-Length: 300\x0d\x0a"

		"Content-Type: text/html"

		"\x0d\x0a\x0d\x0a"

		"<html>\r\n"

			"<head>\r\n"

				"<meta charset=\"UTF-8\">\r\n"

				"<title>Warning Page</title>\r\n"

				"<style>\r\n"

			    		"img {\r\n"

						"position: absolute;\r\n"

						"width: 100%;\r\n"

						"height: 100%;\r\n"

						"top: 50%;\r\n"

						"left: 50%;\r\n"

						"transform: translate(-50%, -50%);\r\n"

			    		"}\r\n"

				"</style>\r\n"

		    "</head>\r\n"

		    "<body>\r\n"

			"<img   src=\"https://i.ibb.co/Lkx6Ywx/1.png\" alter=\"*WARNING*\">\r\n"

		    "</body>\r\n"

		"</html>", post_payload_size);

		

        }

	pseudo_header->tcplength = htons(sizeof(struct tcphdr) + post_payload_size);



	tcphdr->check = in_cksum((u_short*)pseudo_header, sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);  //오류 검출?



	iphdr->version = 4;

	iphdr->ihl = 5; //header length

	iphdr->protocol = IPPROTO_TCP; 

	//iphdr->tot_len = 40;

	iphdr->tot_len = htons(40 + post_payload_size);



	iphdr->id = ((struct iphdr*)(pre_packet + size_vlan + 14))->id + htons(1);



	memset((char*)iphdr + 6, 0x40, 1);



	iphdr->ttl = 60;

	iphdr->saddr = source_address.s_addr;

	iphdr->daddr = dest_address.s_addr;

	// IP 체크섬 계산.

	iphdr->check = in_cksum((u_short*)iphdr, sizeof(struct iphdr));



	address.sin_family = AF_INET;

	address.sin_port = tcphdr->dest;

	address.sin_addr.s_addr = dest_address.s_addr;



#ifdef SUPPORT_OUTPUT

	prt_sendto_payload = 1;

#endif



	if (prt_sendto_payload == 1) {

            	print_chars('\t', 1);

            	printf("        From: %s\n", inet_ntoa(source_address));

            	print_chars('\t', 1);

            	printf("          To: %s\n", inet_ntoa(dest_address));



            	switch (iphdr->protocol) {

            	case IPPROTO_TCP:

                	print_chars('\t', 1);

                	printf("    Protocol: TCP\n");

                	break;

            	case IPPROTO_UDP:

                	print_chars('\t', 6);

                	printf("   Protocol: UDP\n");

                	return -1;

            	case IPPROTO_ICMP:

                	print_chars('\t', 6);

                	printf("   Protocol: ICMP\n");

                	return -1;

            	case IPPROTO_IP:

                	print_chars('\t', 6);

                	printf("   Protocol: IP\n");

                	return -1;

            	case IPPROTO_IGMP:

                	print_chars('\t', 6);

                	printf("   Protocol: IGMP\n");

                	return -1;

            	default:

                	print_chars('\t', 6);

                	printf("   Protocol: unknown\n");

                	//free(packet_dmp);

                	return -2;

                }

                

            	print_chars('\t', 1);

            	printf("    Src port: %d\n", ntohs(tcphdr->source));

            	print_chars('\t', 1);

            	printf("    Dst port: %d\n", ntohs(tcphdr->dest));

            	

#ifdef SUPPORT_OUTPUT

		//m-debug

		printf("Total packet length : %d\n", ntohs(iphdr->tot_len));

#endif



            	payload = (u_char*)(packet + sizeof(struct iphdr) + tcphdr->doff * 4);

            	size_payload = ntohs(iphdr->tot_len) - (sizeof(struct iphdr) + tcphdr->doff * 4);



            	if (size_payload) {

                	print_chars('\t', 6);

                	printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload);

                	//print_payload(payload, size_payload);

                	print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);

            	}



            	if (size_payload) {

                	print_chars('\t', 6);

                	printf("   PACKET-HEADER(try2) (%d bytes):\n", 40);

                	//print_payload(payload, size_payload);

                	print_payload_right((const u_char*)&packet, 40);

            	}



            	if (size_payload) {

                	print_chars('\t', 6);

                	printf("   Payload (%d bytes):\n", size_payload);

                	//print_payload(payload, size_payload);

                	print_payload_right(payload, size_payload);

            	}

	} // end -- if -- prt_sendto_payload = 1 ;

	if (mode == 1) {

		sendto_result = sendto(raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,

						(struct sockaddr*)&address, sizeof(address));

		if (sendto_result != ntohs(iphdr->tot_len)) 	fprintf(stderr, "ERROR: sendto() - %s\n", strerror(errno));



	}

	close(raw_socket);



#ifdef SUPPORT_OUTPUT

	printf("\n[sendraw] End!!! \n\n");

#endif

}// end sendraw function .



int print_chars(char print_char, int nums)

{

	int i = 0;

    	for (i ; i < nums; i++)		printf("%c", print_char);

	return i;

}



void print_hex_ascii_line(const u_char* payload, int len, int offset)

{

	int i;

    	int gap;

    	const u_char* ch;



    	/* offset */

    	printf("%05d   ", offset);



    	/* hex */

    	ch = payload;

    	for (i = 0; i < len; i++) {

		printf("%02x ", *ch);

        	ch++;



        	/* print extra space after 8th byte for visual aid */

        	if (i == 7)

            	printf(" ");

    	}

    	/* print space to handle line less than 8 bytes */

    	if (len < 8)

        	printf(" ");



    	/* fill hex gap with spaces if not full line */

    	if (len < 16) {

        	gap = 16 - len;

        	for (i = 0; i < gap; i++)		printf("   ");

    	}

    	printf("   ");



    	/* ascii (if printable) */

    	ch = payload;

    	for (i = 0; i < len; i++) {

		if (isprint(*ch))		printf("%c", *ch);

		else				printf(".");

        	ch++;

    	}

    	printf("\n");

	return;

}



void	print_hex_ascii_line_right(const u_char* payload, int len, int offset)

{

	int i;

	int gap;

    	const u_char* ch;

    	int tabs_cnt = 6;  // default at now , afterward receive from function caller



    	/* print 10 tabs for output to right area   */

    	for (i = 0; i < tabs_cnt; i++)		printf("\t");



    	/* offset */

    	printf("%05d   ", offset);



    	/* hex */

    	ch = payload;

    	for (i = 0; i < len; i++) {

		printf("%02x ", *ch);

        	ch++;

        	/* print extra space after 8th byte for visual aid */

        	if (i == 7)

            		printf(" ");

    	}

    	/* print space to handle line less than 8 bytes */

    	if (len < 8)

        	printf(" ");



    	/* fill hex gap with spaces if not full line */

    	if (len < 16) {

        	gap = 16 - len;

        	for (i = 0; i < gap; i++)		printf("   ");

    	}

    	printf("   ");



    	/* ascii (if printable) */

    	ch = payload;

    	for (i = 0; i < len; i++) {

        	if (isprint(*ch))		printf("%c", *ch);

		else				printf(".");

        	ch++;

    	}

    	printf("\n");

	return;

}





//print packet payload data (avoid printing binary data)

void print_payload(const u_char* payload, int len)

{

	int len_rem = len;

    	int line_width = 16;         /* number of bytes per line */

    	int line_len;

    	int offset = 0;               /* zero-based offset counter */

    	const u_char* ch = payload;



    	if (len <= 0)	return;



    	/* data fits on one line */

    	if (len <= line_width) {

		print_hex_ascii_line(ch, len, offset);

        	return;

    	}



    	/* data spans multiple lines */

    	for (;; ) {

        	/* compute current line length */

        	line_len = line_width % len_rem;

        	/* print line */

        	print_hex_ascii_line(ch, line_len, offset);

        	/* compute total remaining */

        	len_rem = len_rem - line_len;

        	/* shift pointer to remaining bytes to print */

        	ch = ch + line_len;

        	/* add offset */

        	offset = offset + line_width;

        	/* check if we have line width chars or less */

        	if (len_rem <= line_width) {

            		/* print last line and get out */

            		print_hex_ascii_line(ch, len_rem, offset);

            		break;

        	}

    	}

    	return;

}



//print packet payload data (avoid printing binary data)

void print_payload_right(const u_char* payload, int len)

{

	int len_rem = len;

    	int line_width = 16;         /* number of bytes per line */

    	int line_len;

    	int offset = 0;               /* zero-based offset counter */

    	const u_char* ch = payload;



    	if (len <= 0)	return;



    	/* data fits on one line */

    	if (len <= line_width) {

        	print_hex_ascii_line_right(ch, len, offset);

        	return;

    	}



    	/* data spans multiple lines */

    	for (;; ) {

        	/* compute current line length */

        	line_len = line_width % len_rem;

        	/* print line */

        	print_hex_ascii_line_right(ch, line_len, offset);

        	/* compute total remaining */

        	len_rem = len_rem - line_len;

        	/* shift pointer to remaining bytes to print */

        	ch = ch + line_len;

        	/* add offset */

        	offset = offset + line_width;

        	/* check if we have line width chars or less */

        	if (len_rem <= line_width) {

            		/* print last line and get out */

            		print_hex_ascii_line_right(ch, len_rem, offset);

            		break;

        	}

        	//m-debug

        	if (offset > 600) {

            		print_chars('\t', 6);

            		printf("INFO: ..........    payload too long (print_payload_right func) \n");

            		break;

        	}

    	}

    	return;

}