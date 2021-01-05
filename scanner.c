#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include "radiotap-parser.h"

pcap_t *handle;
char *adapter=(char *)"mon0";   //placa wireless in mod monitorizare
int maxIndexLoop;               // numarul maxim de scanari
int scanningTime;               // periaoada de scanare pentru un canal, in secunde
int *channelsArray;             //lista canalelor suportate
int channelsNumber;             //numarul de canale suportate
int currentChannel;             //canalul pe care este setata placa wireless
int cap_packet_counter=0;       //numarul de pachete capturate
int breakwhileloop=1;           //folosit la intreruperea buclei while din main()

pcap_t * cardInit(char *dev);
int SnifferStart(pcap_t * handle);
int SnifferClose(pcap_t * handle);
void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
int getChannel(char *tmpString,int tmpSize);
int getChannelsNumber(char *tmpString,int tmpSize);
void SIGINThandler(int sigalnr);
void SnifferTerminate(int signum);

pcap_t * cardInit(char *dev){
    char errbuf[PCAP_ERRBUF_SIZE*10];
    int header_type;
    int status=0;
    pcap_t *handle=0;

    handle=pcap_create(dev,errbuf);
    if(handle==NULL)
    {
        fprintf(stderr, "Cannot open device %s: %s\n", dev, errbuf);
        return 0;
    }

    pcap_set_promisc(handle,0);
    pcap_set_snaplen(handle,BUFSIZ);
    
    status=pcap_activate(handle);
    if(status!=0){
        pcap_perror(handle,(char*)"pcap error: ");
        return 0;
    }
    header_type=pcap_datalink(handle);
    if(header_type!=DLT_IEEE802_11_RADIO){
        printf("Error: incorrect header type - %d",header_type);
        return 0;            
    }
    
    return handle;
}

int SnifferStart(pcap_t * handle){
    //signal(SIGALRM,SnifferTerminate);
    alarm(scanningTime);
    pcap_loop(handle,-1,packet_process,NULL);
    return 0;
}

int SnifferClose(pcap_t * handle){
    // Сlose the session
    pcap_close(handle);
    pcap_set_rfmon(handle,0);
    //return 0;
}

void SnifferTerminate(int signum){
    pcap_breakloop(handle);
    //pcap_close(handle);
}

void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    //printf("procesam pachet\n");
    //print_packet_info(packet, *header);
    cap_packet_counter++;
    int8_t rssi=0;
    if(header!=0 && packet!=0){
        printf("Lungime header:%d Lungime captura:%d\n",header->len, header->caplen);
        
        int status=0, next_arg_index=0;
        struct ieee80211_radiotap_header *xheader=(struct ieee80211_radiotap_header *)packet;

        printf("IT_VERSION:%i it_pad:%i it_len:%i it_present:%i\n",xheader->it_version,xheader->it_pad,xheader->it_len,xheader->it_present);

        /*
        struct ieee80211_radiotap_iterator iterator;
        status = ieee80211_radiotap_iterator_init(&iterator,xheader,header->len);
        status=-1;
        do{
            next_arg_index=ieee80211_radiotap_iterator_next(&iterator);        
            if(iterator.this_arg_index==IEEE80211_RADIOTAP_DBM_ANTSIGNAL){
                rssi=*iterator.this_arg;                        
                status=0;
                break;           
            }
        }while(next_arg_index>=0);
        printf("RSSI:%i",rssi);
        */
    } 
    else {
        printf("Eroare la captura ...");
    }
    return;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void initChannelsList(){
    FILE *tmpFile;
    extern FILE *popen();
    char buffer[80];
    char command[80];
    strcpy(command,"iwlist ");
    strcat(command,adapter);
    strcat(command," channel");

    printf("Generam lista canalelor suportate de placa wireless\n");
    printf("===================================================\n");

    /* Open the command for reading. */
    tmpFile = popen(command,"r");
    if (tmpFile == NULL) {
        printf("Nu se poate executa comanda %s. Poate nu sunteti \"root\"?\n",command );
        exit(1);
    }

    if(fgets(buffer, sizeof(buffer), tmpFile) != NULL){
        //printf("%s\n",buffer);
    }
    //din raspuns extragem numarul de canale suportate de placa
    channelsNumber=getChannelsNumber(buffer,sizeof(buffer));
    printf("in functia principala numarul de canale este %d\n", channelsNumber);

    //alocam memoria necesara listei de canale
    channelsArray=malloc(channelsNumber*sizeof(int));
    //populam lista cu canalele suportate
    int i;
    for(i=0;i<channelsNumber;i++){
        if(fgets(buffer, sizeof(buffer), tmpFile) != NULL){
            channelsArray[i]=getChannel(buffer,sizeof(buffer));
            //printf("%d\n", channelsArray[i]);
        }
    }

    /* close */
    pclose(tmpFile);
}

int getChannel(char *tmpString,int tmpSize){

    char tmpBuff[7];
    int pos,i;

    for(i=0;i<tmpSize-7;i++){
        memcpy(tmpBuff,&tmpString[i],7);
        tmpBuff[7]='\0';
        if(strcmp(tmpBuff,"Channel")==0){
            pos=i;
            //printf("gasit pe pozitia %d\n",pos);
        }
    }
    char tmpChannelsNumber[3];
    memcpy(tmpChannelsNumber,&tmpString[pos+8],3);
    tmpChannelsNumber[3]='\0';
    int intChannelsNumber=atoi(tmpChannelsNumber);
    return intChannelsNumber;
}

int getChannelsNumber(char *tmpString,int tmpSize){

    char tmpBuff[8];
    int pos,i;

    for(i=0;i<tmpSize-8;i++){
        memcpy(tmpBuff,&tmpString[i],8);
        tmpBuff[8]='\0';
        if(strcmp(tmpBuff,"channels")==0){
            pos=i;
            //printf("gasit pe pozitia %d\n",pos);
        }
    }

    char tmpChannelsNumber[3];
    memcpy(tmpChannelsNumber,&tmpString[pos-4],3);
    tmpChannelsNumber[3]='\0';
    int intChannelsNumber=atoi(tmpChannelsNumber);
    //printf("numarul de canale este %s sau %d\n",tmpChannelsNumber,intChannelsNumber);
    return intChannelsNumber;
}

void setChannel(int tmpchannel){
    FILE *tmpFile;
    extern FILE *popen();
    char buffer[80];
    char command[80];
    char command2[80];
    strcpy(command,"iw dev ");
    strcat(command,adapter);
    strcat(command," set channel ");
    char tmpCh[4];
    snprintf(tmpCh, 4, "%d", tmpchannel);
    strcat(command,tmpCh);
    strcat(command,"");
    strcpy(command2,"iwconfig mon0");
    tmpFile = popen(command,"r");
    if (tmpFile == NULL) {
        printf("Nu se poate executa comanda %s. Poate nu sunteti \"root\"?\n",command );
        exit(1);
    }

    if(fgets(buffer, sizeof(buffer), tmpFile) != NULL){
        //printf("setare canal :%s\n",buffer);
    }

    currentChannel=tmpchannel;

    pclose(tmpFile);

    tmpFile = popen(command2,"r");
    if (tmpFile == NULL) {
        printf("Nu se poate executa comanda %s. Poate nu sunteti \"root\"?\n",command );
        exit(1);
    }
    if(fgets(buffer, sizeof(buffer), tmpFile) != NULL){
        //printf("citire canal :%s\n",buffer);
    }
    pclose(tmpFile);
}

void SIGINThandler(int sigalnr){
    //este folosita la intreruperea unei bucle while
    //printf("a trecut pe aici SIGINT\n");
    breakwhileloop=0;
}



int main( int argc, char *argv[] ){

    signal(SIGALRM,SnifferTerminate);
    signal(SIGINT,SIGINThandler);

	if(argc ==3){
        maxIndexLoop=atoi(argv[1]);
        scanningTime=atoi(argv[2]);
    } else if(argc ==2) {
        maxIndexLoop=atoi(argv[1]);
        scanningTime=1;
    } else {
        maxIndexLoop=1;
        scanningTime=1;
    }

    initChannelsList();
    int indexLoop=0;
    int indexChannel=0;

    handle=cardInit(adapter);
    if(handle==0)
    {
        printf("error device %s\n", adapter);
        return 1;
    };

    while(indexChannel<channelsNumber && breakwhileloop && indexLoop<maxIndexLoop){
        printf("===Setam canalul:%d=== pentru iteratia:%d\n",channelsArray[indexChannel], indexLoop+1);
        setChannel(channelsArray[indexChannel]);
        SnifferStart(handle);
        indexChannel++;
        if(indexChannel==channelsNumber){
            indexChannel=0;
            indexLoop++;
        }
        //printf("Control variabile: Index canale:%d Numar Canale:%d Break Loop:%d Index Loop:%d\n",indexChannel,channelsNumber,breakwhileloop,indexLoop);
    }
    SnifferClose(handle);
    printf("Numarul de pachete analizate este:%d\n", cap_packet_counter);
    return 0;

}