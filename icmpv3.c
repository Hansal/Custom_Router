#include "headers.h"

// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t icmp4_checksum (struct icmphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

char *find_ip(char *inface)
   {
char *array[10];
array[0]="eth0";
array[1]="10.10.1.2";
array[2]="eth3";
array[3]="10.10.3.1";
array[4]="eth4";
array[5]="10.1.2.1";
int i=0;
while(i<6)
{
   if(strcmp(inface,array[i])==0)
     {
      printf("source ip inside func is %s\n",array[i+1] );
      return array[i+1];
     }
     i+=2;
    
}
printf("function ip_find failed");
return;
}
int
create_icmp (unsigned char* Buffer , int Size, char * ip_port, int sd)
{
  printf("**********ICMP************* port %s size is %d and\n",ip_port,Size);
  int i, status, datalen, frame_length, bytes, *ip_flags;
  char *interface, *target, *src_ip, *dst_ip;
  struct iphdr *ip_instance;
  struct icmphdr *icmp_instance;
  uint8_t *data, *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);
  // new_packet = allocate_ustrmem (IP_MAXPACKET);

  struct sockaddr_in source;

  // Interface to send packet through.
  strcpy (interface, ip_port);
  
//////////////////////////////////Create Source and Dest MAC and get the index of interface/////////////////////////////////
  struct ethhdr *eth = (struct ethhdr *)Buffer;
  memcpy(dst_mac,eth->h_source,6);
  memcpy(src_mac,eth->h_dest,6);

  // Report source MAC address to stdout.
  printf ("Source MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  printf ("Destination MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", dst_mac[i]);
  }
  printf ("%02x\n", dst_mac[5]);
  // return;

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);


////////////////////////////////////////Create IP header now/////////////////////////////////////////



 
  ifr.ifr_addr.sa_family = AF_INET; 
  strcpy(ifr.ifr_name, ip_port);
  strcpy(src_ip,find_ip(ip_port));
  printf("source ip outside func is %s",src_ip);

  
  struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
  ip_instance = (struct iphdr *) malloc (sizeof (struct iphdr));
  memcpy(ip_instance,iph, sizeof(struct iphdr));

  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;

  strcpy(dst_ip,inet_ntoa(source.sin_addr));

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6);
  device.sll_halen = 6;

  // ICMP data
  

  memcpy(data,(Buffer + sizeof (struct ethhdr)), 28);
  printf("String: %s strlen::%d\n", data,strlen(data));
  
 ip_instance->tot_len = htons (IP4_HDRLEN + ICMP_HDRLEN + 28);

  // Time-to-Live (8 bits): default to maximum value
  ip_instance->ttl = 64;

  // Transport layer protocol (8 bits): 1 for ICMP
 ip_instance->protocol = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(ip_instance->saddr))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(ip_instance->daddr))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  ip_instance->check = 0;
  ip_instance->check = checksum ((unsigned short *) ip_instance, IP4_HDRLEN);

  /////////////////////////////////////////// ICMP header///////////////////////////////////////////////

  // Message Type (8 bits): time exceeded
  icmp_instance = (struct icmphdr *) malloc (sizeof (struct icmphdr));
  icmp_instance->type = ICMP_TIME_EXCEEDED;

  // Message Code (8 bits): time exceeded
 icmp_instance->code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  // icmphdr.icmp_id = htons (1000);
  icmp_instance->un.echo.id = 0x1337;

  // Sequence Number (16 bits): starts at 0
  icmp_instance->un.echo.sequence = 0;
  icmp_instance->checksum=0;
  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6);
  memcpy (ether_frame + 6, src_mac, 6);
  
  ether_frame[12] = ETH_P_IP / 256;
  ether_frame[13] = ETH_P_IP % 256;

  // IPv4 header
  memcpy (ether_frame + ETH_HDRLEN, ip_instance, IP4_HDRLEN);

  // ICMP header
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, icmp_instance, ICMP_HDRLEN);

  // ICMP data
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, (Buffer  + sizeof(struct ethhdr)), 28);
  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  icmp_instance->checksum = icmp4_checksum(*icmp_instance,data,28);
  
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + 28;

  // ICMP header
  memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, icmp_instance, ICMP_HDRLEN);

  // Send ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (data);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);

  return (EXIT_SUCCESS);
}

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t
icmp4_checksum (struct icmphdr icmphdr_new, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy Message Type to buf (8 bits)
  memcpy (ptr, &icmphdr_new.type, sizeof (icmphdr_new.type));
  ptr += sizeof (icmphdr_new.type);
  chksumlen += sizeof (icmphdr_new.type);

  // Copy Message Code to buf (8 bits)
  memcpy (ptr, &icmphdr_new.code, sizeof (icmphdr_new.code));
  ptr += sizeof (icmphdr_new.code);
  chksumlen += sizeof (icmphdr_new.code);

  // Copy ICMP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy Identifier to buf (16 bits)
  memcpy (ptr, &icmphdr_new.un.echo.id, sizeof (icmphdr_new.un.echo.id));
  ptr += sizeof (icmphdr_new.un.echo.id);
  chksumlen += sizeof (icmphdr_new.un.echo.id);

  // Copy Sequence Number to buf (16 bits)
  memcpy (ptr, &icmphdr_new.un.echo.sequence, sizeof (icmphdr_new.un.echo.sequence));
  ptr += sizeof (icmphdr_new.un.echo.sequence);
  chksumlen += sizeof (icmphdr_new.un.echo.sequence);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}


// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}
