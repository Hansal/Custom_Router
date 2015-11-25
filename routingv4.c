#include "headers.h"

struct routing
{
  char subnet[20],ip[20],eth[5],mac[20];
  struct routing *next;
}*routing_table=NULL;

struct routing *current;

struct lookup *ip_search(char *ip_addr, int input_flag)
{
  struct routing *new_node;
  new_node=routing_table;int i=0,flag=0;
  if (input_flag == 1)
  {
    while(new_node!=NULL) 
    {
      if (memcmp(new_node->subnet,ip_addr,7)==0)
      {
        
        // strcpy(look_up->eth,new_node->eth);
        look_up->eth=new_node->eth;
        // strcpy(look_up->lookup_mac,new_node->mac);
        look_up->lookup_mac=new_node->mac;
        flag=1;        
        break;
      }
      new_node=new_node->next;
    }
    /*if (flag == 0)
    {
      // printf("There is no such entry for %s\n",ip_addr);
    }*/
  }
  else if (input_flag == 3)
  {
    // strcpy(look_up->eth,"eth4");
    look_up->eth="eth4";
    // strcpy(look_up->lookup_mac,"00:04:23:a6:58:16");
    look_up->lookup_mac="00:04:23:a6:58:16";
  }
  else
  {
    // printf("Input flag%d\n", input_flag);
    // strcpy(look_up->eth,"eth4");
    look_up->eth="eth4";
    // strcpy(look_up->lookup_mac,"00:04:23:a6:b2:99");
    look_up->lookup_mac="00:04:23:a6:b2:99";
  }

return look_up;
}

void insert(char *subnet, char *ip_addr,char *mac_addr, char *intf)
{
  struct routing *new_node;

  new_node=(struct routing *)malloc(sizeof(struct routing));
  strcpy(new_node->ip,ip_addr);
  strcpy(new_node->subnet,subnet);
  strcpy(new_node->mac,mac_addr);
  strcpy(new_node->eth,intf);
  
  new_node->next=NULL;

  if(routing_table==NULL)
  {
    routing_table=new_node;
    current=new_node;
  }
  else
  {
    current->next=new_node;
    current=new_node;
    
  }

}

void display()
{
  struct routing *new_node;
  new_node=routing_table;int i=0;
  while(new_node!=NULL)   
  {
    printf("%d %s   %s  %s\t %s\n",i++,new_node->subnet, new_node->ip,new_node->eth,new_node->mac);

    new_node=new_node->next;
  }
}


int read_arp(char *list)
{
  FILE * fp1,*fp2;
  char buf[1024],line1[100],line2[100];
  //fgets (line, 100, fp);
  char ip[20],flag_1[10],flag_2[10],mac[20],star[5],interface[0],subnet_id[20];
  int count=0;
  // fp = fopen ("/proc/net/arp", "r");
  //printf("In the read_arp function\n");
  fp1 = fopen("arp.txt","r");

  if(fp1 == NULL)
  {
    perror("Error opening file");
    return(-1);
  }

  fp2 = fopen("routing.txt","r");
  if(fp2 == NULL)
  {
    perror("Error opening file");
    return(-1);
  }
  
  while ( fgets (line1, 100, fp1)!=NULL )
  {
    
    sscanf(line1, "%s %s %s %s %s %s",ip,flag_1,flag_2,mac,star,interface);

    if(fgets (line2, 100, fp2)!=NULL)
    {
      sscanf(line2, "%s ",subnet_id);
    }
    insert(subnet_id,ip,mac,interface);
    strcat(list,interface);
    strcat(list,"\t");

  }
  fclose(fp1);
  fclose(fp2);
  return 0;
}

void mac_lookup(char *port,char *result)

{
  if (memcmp(port,"eth0",4)==0)
  {
    // printf("IT is eth0\n");
    // strcpy(result,"00:04:23:a6:cd:1a");
    memcpy(result,"00:04:23:a6:cd:1a",17);
  }
  else if ( memcmp(port,"eth3",4)==0)
  {
    // printf("IT is eth3\n");
    memcpy(result,"00:04:23:a6:bb:80",17);
  }
  else if (memcmp( port,"eth4",4)==0)
  {
    // printf("IT is eth4\n");
    memcpy(result,"00:04:23:a6:bb:81",17);
  }
  else
  {
    // printf("NEVER COME HERE::::\n");
    //memcpy(result,"00:04:23:ee:dd:ff",17);
  }
}

