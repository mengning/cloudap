#include<stdio.h>
#include<arpa/inet.h>
#include<assert.h>
#include<string.h>

#define PORT                    5001
#define IP_ADDR                 "127.0.0.1"
#define MAX_CONNECT_QUEUE       1024
#define MAX_BUF_LEN             1024
int main()
{
    printf("nl80211ext: %s\n",__FUNCTION__ );
    int fd = -1;
    int ret = -1;
    char buf[MAX_BUF_LEN];
    struct sockaddr_in serveradd;
    struct sockaddr_in clientaddr;
    socklen_t clientaddr_len = sizeof(struct sockaddr);
    serveradd.sin_family = AF_INET;
    serveradd.sin_port = ntohs(PORT);
    serveradd.sin_addr.s_addr = inet_addr(IP_ADDR);
    bzero(&(serveradd.sin_zero),8);
    fd = socket(PF_INET,SOCK_STREAM,0);
    assert(fd != -1);
    ret = bind(fd,(struct sockaddr *)&serveradd,sizeof(struct sockaddr));
    if(ret == -1)
    {
        fprintf(stderr,"Bind Error %s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    ret = listen(fd,MAX_CONNECT_QUEUE);
    assert(ret != -1);
    while(1)
    {
        int newfd = accept(fd,(struct sockaddr *)&clientaddr,&clientaddr_len);
        if(newfd == -1)
        {
            fprintf(stderr,"Accept Error,%s:%d\n",__FILE__,__LINE__);
        }

        ret = send(newfd,"hi",sizeof("hi"),0);
        if(ret > 0)
        {
            printf("send \"hi\" to %s:%d\n",(char*)inet_ntoa(clientaddr.sin_addr),ntohs(clientaddr.sin_port));
        }
        ret = recv(newfd,buf,MAX_BUF_LEN,0);
        if(ret > 0)
        {
            printf("recv \"%s\" from %s:%d\n",buf,(char*)inet_ntoa(clientaddr.sin_addr),ntohs(clientaddr.sin_port));   
        }
        close(newfd);
    }
    close(fd);  
}