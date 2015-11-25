#include "headers.h"

char *interface_port[4];
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j,sd,sd1,sd2;
int bytes=0;
uint8_t *src_mac, *dst_mac, *ether_frame,*octet;

void ProcessPacket(unsigned char* , int,long);
int print_icmp_packet(unsigned char* , int,long );

struct lookup *lp;
struct ether_addr *ea_s;
struct ether_addr *ea_d;
struct iphdr *iph;
struct sockaddr_ll device;
int count =0;
uint32_t prev;

/////////first procedure//////
void *packet_sniff(void *threadid)
{
    long tid;
    tid = (long) threadid;
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct  ifreq ifr_recv;

    unsigned char *buffer = (unsigned char *) malloc(2000); //Its Big!
    struct sockaddr_ll dev;
    memset(&ifr_recv,0, sizeof (ifr_recv));
    memset (&dev, 0, sizeof (dev));
    char *interface_recv;
    interface_recv=(char *)allocate_strmem(5);
    memcpy(interface_recv,interface_port[tid],4);

    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;

    memcpy((char *)ifr_recv.ifr_name,(char *)interface_recv,IFNAMSIZ);

    dev.sll_family=AF_PACKET;
    dev.sll_protocol=htons(ETH_P_IP);
    if ((dev.sll_ifindex = if_nametoindex (interface_recv)) == 0) {
      perror ("if_nametoindex() failed to obtain interface index ");
      exit (EXIT_FAILURE);
    }

    if(bind(sock_raw,(struct sockaddr *)&dev, sizeof(dev))==-1)
    {
      perror("error to bind");
      exit(-1);
    }

    if(sock_raw < 0)
    {
        //Print the error with proper message
      perror("Socket Error");
      //return 1;
    }
    while(1)
    {
      saddr_size = sizeof saddr;
      data_size = recvfrom(sock_raw , buffer , 65536 , 0 , (struct sockaddr *)&dev , (socklen_t*)&saddr_size);
      if(data_size <0 )
      {
        printf("Recvfrom error , failed to get packets\n");
        //return 1;
      }
        //Now process the packet
      if((dev.sll_pkttype)==PACKET_HOST)
      {
        // printf("*******************NOT A OUTGOING PACKET************************\n");
        // continue;
        iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;
        if (memcmp(inet_ntoa(dest.sin_addr),"192.168.252.1",4)==0){
          continue;
        }
        print_icmp_packet(buffer , data_size,tid);
      }
    }
    close(sock_raw);
    printf("Finished");
    pthread_exit(NULL);
}


  int main()
  {
  //////////////////// from routing.c/////////////
    lp=(struct lookup *)malloc(sizeof(struct lookup));
    ea_s=(struct ether_addr *)malloc(sizeof(struct ether_addr)); 
    ea_d=(struct ether_addr *)malloc(sizeof(struct ether_addr)); 
    octet= (uint8_t *)allocate_ustrmem (6);
    look_up=(struct lookup *)malloc(sizeof(struct lookup));
    memset (&device, 0, sizeof (device));

    //memset (&prev, 0, sizeof (prev));
    //prev->daddr=0xffffffff;
    char eth_list[100]={0};
    if (read_arp(eth_list) < 0)
    {
      perror("Error opening file");
      return(-1);
    }
    eth_list[strlen(eth_list)-1]='\0';
    char duplicat_list[strlen(eth_list)];
    memcpy(duplicat_list,eth_list,strlen(eth_list));
    char *pch;int j=0;
    pch = strtok (eth_list," \t");
    interface_port[j++]=pch;
    while (pch != NULL)
    {
      pch = strtok (NULL, " \t");
      if (pch != NULL)
        interface_port[j++]=pch;
    }
  //////////////////////

    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) 
    {
      perror ("socket() failed ");
      exit (EXIT_FAILURE);
    }

  ////////////from main.c///////
    pthread_t threads[NUM_THREADS];
    int rc;
    long t;
    for (t = 0; t < NUM_THREADS; t++)
    {
      rc = pthread_create(threads + t, NULL, packet_sniff, (void *) t);
      if (rc)
      {
        printf("ERROR; return code from pthread_create() is %d\n", rc);
        exit(-1);
      }
    }

    for (t = 0; t < NUM_THREADS; t++)
    {
      pthread_join(threads[t], NULL);
    }
    return 0;
  }


int print_icmp_packet(unsigned char* Buffer , int Size, long id)
    {
      

/////////////////////////////////////// Start lookup here/////////////////////////////////////////////

  if(iph->daddr!=prev)
  {
    //printf("hello\n");
    prev=iph->daddr;
    //printf("Before:::ETH %s\n\t MAC %s\n",lp->eth,lp->lookup_mac);
    if (memcmp(inet_ntoa(dest.sin_addr),"10.1.2.0",7)==0){
      if (memcmp(inet_ntoa(dest.sin_addr),"10.1.2.3",8)==0){
        // no need of next hop, just send by attaching the MAC, i.e. call ip_search() with some flag
        // printf("IT is 10.1.2.3\n");
        lp = (struct lookup *)ip_search(inet_ntoa(dest.sin_addr),3);
      }
      else{
        // no need of next hop, just send by attaching the MAC, i.e. call ip_search() with some flag
        // printf("IT is 10.1.2.4\n");
        lp = (struct lookup *)ip_search(inet_ntoa(dest.sin_addr),4);
      }
      // printf("!!!!!!!!!!!@@@@@@@@@@@@@@@####################$$$$$$$$$$$$$$$$$$$$$$$$^^^^^^^^^^^^^^^^^^^06\n" );
    }
    else{
      // call ip_search() without the flag, normal lookup
      // printf("Normal lookup\n");
      lp=(struct lookup *)ip_search(inet_ntoa(dest.sin_addr),1);
    }
    if ((device.sll_ifindex = if_nametoindex (lp->eth)) == 0) 
    {
      perror ("if_nametoindex() failed to obtain interface index ");
      exit (EXIT_FAILURE);
    }
    //printf("after loop\n");
    char mac[20]={0};
    ea_d=(ether_aton(lp->lookup_mac));
    memcpy(octet,ea_d->ether_addr_octet,6);
    mac_lookup(lp->eth,mac);
    ea_s=(ether_aton(mac));

    if (iph->ttl == 1)
    {
    // we need to create ICMP packet!!!!!!!
    create_icmp(Buffer ,Size, interface_port[id],sd);
    return;
    }



  }
      //printf("After::: ETH %s\n\t MAC %s\n",lp->eth,lp->lookup_mac);
/////////////////////////////////////// End lookup here/////////////////////////////////////////////



    memcpy (Buffer, octet, 6);
    memcpy (Buffer+6, ea_s->ether_addr_octet, 6);

    // Send ethernet frame to socket.
    if ((bytes = sendto (sd, Buffer, Size, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) 
    {
      perror ("sendto() failed");
      exit (EXIT_FAILURE);
    }
    // printf("******PACKET SENT ******\n");
    return 1;
  }