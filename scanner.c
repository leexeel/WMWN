#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include "radiotap-parser.h"

#include "scanner.h"
#include "dbaccess.h"

pcap_t *cardInit(char *dev);
int SnifferStart(pcap_t *handle);
int SnifferClose(pcap_t *handle);
void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void get_radio_parameters(const u_char *packet, int len);
void get_frame_parameters(const u_char *packet, const struct pcap_pkthdr *header);
int getChannel(char *tmpString, int tmpSize);
int getChannelsNumber(char *tmpString, int tmpSize);
void getChannelName(int channel);
void SIGINThandler(int sigalnr);
void SnifferTerminate(int signum);
void initRawData();
void addRowData();

pcap_t *cardInit(char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE * 10];
    int header_type;
    int status = 0;
    pcap_t *handle = 0;

    handle = pcap_create(dev, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Cannot open device %s: %s\n", dev, errbuf);
        return 0;
    }

    pcap_set_promisc(handle, 0);
    pcap_set_snaplen(handle, BUFSIZ);

    status = pcap_activate(handle);
    if (status != 0)
    {
        pcap_perror(handle, (char *)"pcap error: ");
        return 0;
    }
    header_type = pcap_datalink(handle);
    if (header_type != DLT_IEEE802_11_RADIO)
    {
        printf("Error: incorrect header type - %d", header_type);
        return 0;
    }

    return handle;
}

int SnifferStart(pcap_t *handle)
{
    //signal(SIGALRM,SnifferTerminate);
    alarm(scanningTime);
    pcap_loop(handle, -1, packet_process, NULL);
    return 0;
}

int SnifferClose(pcap_t *handle)
{
    // Сlose the session
    pcap_close(handle);
    pcap_set_rfmon(handle, 0);
    //return 0;
}

void SnifferTerminate(int signum)
{
    pcap_breakloop(handle);
    //pcap_close(handle);
}

void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    cap_packet_counter++;
    initRawData();
    rd.channel = currentChannel;
    if (header != 0 && packet != 0)
    {
        get_radio_parameters(packet, header->len);
        get_frame_parameters(packet, header);
        if (doNotRecord == 0)
        {
            addRowData();
        }
        else
        {
            doNotRecord = 0;
        }
    }
    else
    {
        printf("Eroare la captura ...");
    }
}

void get_radio_parameters(const u_char *packet, int len)
{
    int status = 0, next_arg_index = 0;
    int8_t rssi_dbm, rssi_db, noise_dbm, noise_db;
    int16_t channel1, channel2;

    struct ieee80211_radiotap_header *header = (struct ieee80211_radiotap_header *)packet;
    struct ieee80211_radiotap_iterator iterator;
    status = ieee80211_radiotap_iterator_init(&iterator, header, len);
    do
    {
        next_arg_index = ieee80211_radiotap_iterator_next(&iterator);
        switch (iterator.this_arg_index)
        {
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            rssi_dbm = *iterator.this_arg;
            rd.rssi = rssi_dbm;
            break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            noise_dbm = *iterator.this_arg;
            //printf("Noise DBM:%i\n", noise_dbm);
            break;
        case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
            rssi_db = *iterator.this_arg;
            //printf("RSSI DB:%i\n", rssi_db);
            break;
        case IEEE80211_RADIOTAP_DB_ANTNOISE:
            noise_db = *iterator.this_arg;
            //printf("Noise DB:%i\n", noise_db);
            break;
        case IEEE80211_RADIOTAP_CHANNEL:
            channel1 = *iterator.this_arg;
            if(channel1 < 0)
            {
                channel1 = -channel1;
            }
            channel2 = *(iterator.this_arg + 1);
            printf("IEEE80211_RADIOTAP_CHANNEL : %d * 256 + %d = %d\n", channel2, channel1, channel2 * 256 + channel1);
            rd.apChannel = channel2 * 256 + channel1;
            rd.apChannel2 = rd.apChannel;
            getChannelName(rd.apChannel);
            break;
        default:
            break;
        }
    } while (next_arg_index >= 0);
}

void get_frame_parameters(const u_char *packet, const struct pcap_pkthdr *header)
{
    if (header->caplen < sizeof(struct ieee80211_radiotap_header))
    {
        //printf("Problema 1 ---------------------------------------------------\n");
        doNotRecord = 1;
    }
    else
    {
        struct ieee80211_radiotap_header *radiotap = (struct ieee80211_radiotap_header *)packet;
        if (header->caplen < radiotap->it_len + sizeof(struct mgmt_header_t))
        {
            //printf("Problema 2 ---------------------------------------------------\n");
            doNotRecord = 1;
        }
        else
        {
            struct mgmt_header_t *mgmt_frame = (struct mgmt_header_t *)(packet + radiotap->it_len);
            //printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x - %02x:%02x:%02x:%02x:%02x:%02x - %02x:%02x:%02x:%02x:%02x:%02x\n", mgmt_frame->da[0], mgmt_frame->da[1], mgmt_frame->da[2], mgmt_frame->da[3], mgmt_frame->da[4], mgmt_frame->da[5], mgmt_frame->sa[0], mgmt_frame->sa[1], mgmt_frame->sa[2], mgmt_frame->sa[3], mgmt_frame->sa[4], mgmt_frame->sa[5], mgmt_frame->bssid[0], mgmt_frame->bssid[1], mgmt_frame->bssid[2], mgmt_frame->bssid[3], mgmt_frame->bssid[4], mgmt_frame->bssid[5]);
            //printf("FC: %02x %02x\n", mgmt_frame->fc[0], mgmt_frame->fc[1]);
            sprintf(rd.bs, "%02x:%02x:%02x:%02x:%02x:%02x", mgmt_frame->bssid[0], mgmt_frame->bssid[1], mgmt_frame->bssid[2], mgmt_frame->bssid[3], mgmt_frame->bssid[4], mgmt_frame->bssid[5]);
            sprintf(rd.da, "%02x:%02x:%02x:%02x:%02x:%02x", mgmt_frame->da[0], mgmt_frame->da[1], mgmt_frame->da[2], mgmt_frame->da[3], mgmt_frame->da[4], mgmt_frame->da[5]);
            sprintf(rd.sa, "%02x:%02x:%02x:%02x:%02x:%02x", mgmt_frame->sa[0], mgmt_frame->sa[1], mgmt_frame->sa[2], mgmt_frame->sa[3], mgmt_frame->sa[4], mgmt_frame->sa[5]);

            int version = mgmt_frame->fc[0] & 0x03;    //trebuie sa fie 0 tot timpul
            int frame_type = mgmt_frame->fc[0] & 0x0C; //masca 00001100 extrage tipul
            frame_type = frame_type >> 2;
            int frame_subtype = mgmt_frame->fc[0] >> 4; //subtip
            rd.direction = mgmt_frame->fc[1] & 0x03;
            //rd.direction = mgmt_frame->fc[1] >> 6;     // masca 11000000 extrage ToDS/FromDS
            if (version > 0)
            {
                printf("cauta alta varianta #####################################################################################################");
            }
            //printf("Versiune: %d Frame: %d Subtip: %d Directie: %d\n", version, frame_type, frame_subtype, direction);
            switch (frame_type)
            {
            case Management:
                //printf("Frame type - Management ============================================================================================\n");
                strcpy(rd.frameType, "Management");
                switch (frame_subtype)
                {
                case ProbeRequest:
                    strcpy(rd.frameSubtype, "ProbeRequest");
                    break;
                case ProbeResponse:
                    strcpy(rd.frameSubtype, "ProbeResponse");
                    break;
                case Beacon:
                    strcpy(rd.frameSubtype, "Beacon");
                    const u_char *location, *length;
                    /*
                    la calcularea locatiei se aduna 12 octeti:
                    - Timestamp         - 8
                    - Beacon Interval   - 2
                    - Capability info   - 2
                    */
                    location = packet + radiotap->it_len + sizeof(struct mgmt_header_t) + 12;
                    length = location + 1;
                    char *ssid = malloc(33);
                    strncpy(ssid, location + 2, *length);
                    ssid[*length] = '\0';
                    strcpy(rd.ssid, ssid);
                    //printf("Element ID: %d Element Length: %d SSID:%s\n",*location,*length,ssid);
                    break;
                case AssociationRequest:
                    strcpy(rd.frameSubtype, "AssociationRequest");
                    break;
                case AssociationResponse:
                    strcpy(rd.frameSubtype, "AssociationResponse");
                    break;
                default:
                    break;
                }
                break;
            case Control:
                //printf("Frame type - Control ============================================================================================\n");
                strcpy(rd.frameType, "Control");
                strcpy(rd.frameSubtype, "-");
                break;
            case Data:
                //printf("Frame type - Data ============================================================================================\n");
                strcpy(rd.frameType, "Data");
                strcpy(rd.frameSubtype, "-");
                break;
            case Extension:
                //printf("Frame type - Extension ============================================================================================\n");
                strcpy(rd.frameType, "Extension");
                strcpy(rd.frameSubtype, "-");
                break;
            default:
                strcpy(rd.frameType, "Ciudatenie");
                strcpy(rd.frameSubtype, "De verificat");
                break;
            }
        }
    }
}

void initChannelsList()
{
    FILE *tmpFile;
    extern FILE *popen();
    char buffer[80];
    char command[80];
    strcpy(command, "iwlist ");
    strcat(command, adapter);
    strcat(command, " channel");

    printf("Generam lista canalelor suportate de placa wireless\n");
    printf("===================================================\n");

    /* Open the command for reading. */
    tmpFile = popen(command, "r");
    if (tmpFile == NULL)
    {
        printf("Nu se poate executa comanda %s. Poate nu sunteti \"root\"?\n", command);
        exit(1);
    }

    if (fgets(buffer, sizeof(buffer), tmpFile) != NULL)
    {
        //printf("%s\n",buffer);
    }
    //din raspuns extragem numarul de canale suportate de placa
    channelsNumber = getChannelsNumber(buffer, sizeof(buffer));
    printf("in functia principala numarul de canale este %d\n", channelsNumber);

    //alocam memoria necesara listei de canale
    channelsArray = malloc(channelsNumber * sizeof(int));
    //populam lista cu canalele suportate
    int i;
    for (i = 0; i < channelsNumber; i++)
    {
        if (fgets(buffer, sizeof(buffer), tmpFile) != NULL)
        {
            channelsArray[i] = getChannel(buffer, sizeof(buffer));
            //printf("%d\n", channelsArray[i]);
        }
    }

    /* close */
    pclose(tmpFile);
}

int getChannel(char *tmpString, int tmpSize)
{

    char tmpBuff[7];
    int pos, i;

    for (i = 0; i < tmpSize - 7; i++)
    {
        memcpy(tmpBuff, &tmpString[i], 7);
        tmpBuff[7] = '\0';
        if (strcmp(tmpBuff, "Channel") == 0)
        {
            pos = i;
            //printf("gasit pe pozitia %d\n",pos);
        }
    }
    char tmpChannelsNumber[3];
    memcpy(tmpChannelsNumber, &tmpString[pos + 8], 3);
    tmpChannelsNumber[3] = '\0';
    int intChannelsNumber = atoi(tmpChannelsNumber);
    return intChannelsNumber;
}

int getChannelsNumber(char *tmpString, int tmpSize)
{

    char tmpBuff[8];
    int pos, i;

    for (i = 0; i < tmpSize - 8; i++)
    {
        memcpy(tmpBuff, &tmpString[i], 8);
        tmpBuff[8] = '\0';
        if (strcmp(tmpBuff, "channels") == 0)
        {
            pos = i;
            //printf("gasit pe pozitia %d\n",pos);
        }
    }

    char tmpChannelsNumber[3];
    memcpy(tmpChannelsNumber, &tmpString[pos - 4], 3);
    tmpChannelsNumber[3] = '\0';
    int intChannelsNumber = atoi(tmpChannelsNumber);
    //printf("numarul de canale este %s sau %d\n",tmpChannelsNumber,intChannelsNumber);
    return intChannelsNumber;
}

void getChannelName(int channel)
{
    switch (channel)
    {
    case 2412:
        rd.apChannel = 1;
        break;
    case 2417:
        rd.apChannel = 2;
        break;
    case 2422:
        rd.apChannel = 3;
        break;
    case 2427:
        rd.apChannel = 4;
        break;
    case 2432:
        rd.apChannel = 5;
        break;
    case 2437:
        rd.apChannel = 6;
        break;
    case 2442:
        rd.apChannel = 7;
        break;
    case 2447:
        rd.apChannel = 8;
        break;
    case 2452:
        rd.apChannel = 9;
        break;
    case 2457:
        rd.apChannel = 10;
        break;
    case 2462:
        rd.apChannel = 11;
        break;
    case 2467:
        rd.apChannel = 12;
        break;
    case 2472:
        rd.apChannel = 13;
        break;
    case 5160:
        rd.apChannel = 32;
        break;
    case 5170:
        rd.apChannel = 34;
        break;
    case 5180:
        rd.apChannel = 36;
        break;
    case 5190:
        rd.apChannel = 38;
        break;
    case 5200:
        rd.apChannel = 40;
        break;
    case 5210:
        rd.apChannel = 42;
        break;
    case 5220:
        rd.apChannel = 44;
        break;
    case 5230:
        rd.apChannel = 46;
        break;
    case 5240:
        rd.apChannel = 48;
        break;
    case 5250:
        rd.apChannel = 50;
        break;
    case 5260:
        rd.apChannel = 52;
        break;
    case 5270:
        rd.apChannel = 54;
        break;
    case 5280:
        rd.apChannel = 56;
        break;
    case 5290:
        rd.apChannel = 58;
        break;
    case 5300:
        rd.apChannel = 60;
        break;
    case 5310:
        rd.apChannel = 62;
        break;
    case 5320:
        rd.apChannel = 64;
        break;
    case 5340:
        rd.apChannel = 68;
        break;
    case 5480:
        rd.apChannel = 96;
        break;
    case 5500:
        rd.apChannel = 100;
        break;
    case 5510:
        rd.apChannel = 102;
        break;
    case 5520:
        rd.apChannel = 104;
        break;
    case 5530:
        rd.apChannel = 106;
        break;
    case 5540:
        rd.apChannel = 108;
        break;
    case 5550:
        rd.apChannel = 110;
        break;
    case 5560:
        rd.apChannel = 112;
        break;
    case 5570:
        rd.apChannel = 114;
        break;
    case 5580:
        rd.apChannel = 116;
        break;
    case 5590:
        rd.apChannel = 118;
        break;
    case 5600:
        rd.apChannel = 120;
        break;
    case 5610:
        rd.apChannel = 122;
        break;
    case 5620:
        rd.apChannel = 124;
        break;
    case 5630:
        rd.apChannel = 126;
        break;
    case 5640:
        rd.apChannel = 128;
        break;
    case 5660:
        rd.apChannel = 132;
        break;
    case 5670:
        rd.apChannel = 134;
        break;
    case 5680:
        rd.apChannel = 136;
        break;
    case 5690:
        rd.apChannel = 138;
        break;
    case 5700:
        rd.apChannel = 140;
        break;
    case 5710:
        rd.apChannel = 142;
        break;
    case 5720:
        rd.apChannel = 144;
        break;
    case 5745:
        rd.apChannel = 149;
        break;
    case 5755:
        rd.apChannel = 151;
        break;
    case 5765:
        rd.apChannel = 153;
        break;
    case 5775:
        rd.apChannel = 155;
        break;
    case 5785:
        rd.apChannel = 157;
        break;
    case 5795:
        rd.apChannel = 159;
        break;
    case 5805:
        rd.apChannel = 161;
        break;
    case 5825:
        rd.apChannel = 165;
        break;
    case 5845:
        rd.apChannel = 169;
        break;
    case 5865:
        rd.apChannel = 173;
        break;
    case 4915:
        rd.apChannel = 183;
        break;
    case 4920:
        rd.apChannel = 184;
        break;
    case 4925:
        rd.apChannel = 185;
        break;
    case 4935:
        rd.apChannel = 187;
        break;
    case 4940:
        rd.apChannel = 188;
        break;
    case 4945:
        rd.apChannel = 189;
        break;
    case 4960:
        rd.apChannel = 192;
        break;
    case 4980:
        rd.apChannel = 196;
        break;
    default:
        rd.apChannel = 200;
        break;
    }
}

void setChannel(int tmpchannel)
{
    FILE *tmpFile;
    extern FILE *popen();
    char buffer[80];
    char command[80];
    char command2[80];
    strcpy(command, "iw dev ");
    strcat(command, adapter);
    strcat(command, " set channel ");
    char tmpCh[4];
    snprintf(tmpCh, 4, "%d", tmpchannel);
    strcat(command, tmpCh);
    strcat(command, "");
    strcpy(command2, "iwconfig mon0");
    tmpFile = popen(command, "r");
    if (tmpFile == NULL)
    {
        printf("Nu se poate executa comanda %s. Poate nu sunteti \"root\"?\n", command);
        exit(1);
    }

    if (fgets(buffer, sizeof(buffer), tmpFile) != NULL)
    {
        //printf("setare canal :%s\n",buffer);
    }
    currentChannel = tmpchannel;
    pclose(tmpFile);
    tmpFile = popen(command2, "r");
    if (tmpFile == NULL)
    {
        printf("Nu se poate executa comanda %s. Poate nu sunteti \"root\"?\n", command);
        exit(1);
    }
    if (fgets(buffer, sizeof(buffer), tmpFile) != NULL)
    {
        //printf("citire canal :%s\n",buffer);
    }
    pclose(tmpFile);
}

void SIGINThandler(int sigalnr)
{
    //este folosita la intreruperea unei bucle while
    //printf("a trecut pe aici SIGINT\n");
    breakwhileloop = 0;
}

void initRawData()
{
    strcpy(rd.frameType, "");
    strcpy(rd.frameSubtype, "");
    rd.direction = 0;
    rd.channel = 0;
    rd.apChannel = 0;
    strcpy(rd.da, "");
    strcpy(rd.sa, "");
    strcpy(rd.bs, "");
    strcpy(rd.ssid, "");
    strcpy(rd.summaryHash, "");
    rd.rssi = 0;
    rd.apChannel2 = 0;
}

void addRowData()
{
    char currentChannelChar[4];
    sprintf(currentChannelChar, "%d", currentChannel);
    char apCurrentChannelChar[4];
    sprintf(apCurrentChannelChar, "%d", rd.apChannel);
    char apCurrentChannel2Char[4];
    sprintf(apCurrentChannel2Char, "%d", rd.apChannel2);
    char rssiChar[4];
    sprintf(rssiChar, "%d", rd.rssi);
    char directionChar[4];
    sprintf(directionChar, "%d", direction);

    //generam comanda pentru mysql
    char query[1024] = "";
    strcat(query, "insert into rowData values (0,NOW(),\"");
    strcat(query, rd.frameType);
    strcat(query, "\",\"");
    strcat(query, rd.frameSubtype);
    strcat(query, "\",");
    strcat(query, directionChar);
    strcat(query, ",");
    strcat(query, currentChannelChar);
    strcat(query, ",");
    strcat(query, apCurrentChannelChar);
    strcat(query, ",\"");
    strcat(query, rd.da);
    strcat(query, "\",\"");
    strcat(query, rd.sa);
    strcat(query, "\",\"");
    strcat(query, rd.bs);
    strcat(query, "\",\"");
    strcat(query, rd.ssid);
    strcat(query, "\",\"");
    strcat(query, rd.summaryHash);
    strcat(query, "\",");
    strcat(query, rssiChar);
    strcat(query, ",");
    strcat(query, apCurrentChannel2Char);
    //strcat(query, "0");
    strcat(query, ")");
    //strcat(query,") ON DUPLICATE KEY UPDATE timestamp=NOW()");
    //printf("trimis in mysql %s\n", query);

    if (mysql_query(connServer, query))
    {
        fprintf(stderr, "%s\n", mysql_error(connServer));
        exit(1);
    }
}

int main(int argc, char *argv[])
{

    signal(SIGALRM, SnifferTerminate);
    signal(SIGINT, SIGINThandler);

    if (argc == 3)
    {
        maxIndexLoop = atoi(argv[1]);
        scanningTime = atoi(argv[2]);
    }
    else if (argc == 2)
    {
        maxIndexLoop = atoi(argv[1]);
        scanningTime = 1;
    }
    else
    {
        maxIndexLoop = 1;
        scanningTime = 1;
    }
    mysqlServerConn(1);
    initChannelsList();
    int indexLoop = 0;
    int indexChannel = 0;

    handle = cardInit(adapter);
    if (handle == 0)
    {
        printf("error device %s\n", adapter);
        return 1;
    };

    while (indexChannel < channelsNumber && breakwhileloop && indexLoop < maxIndexLoop)
    {
        printf("===Setam canalul:%d=== pentru iteratia:%d\n", channelsArray[indexChannel], indexLoop + 1);
        setChannel(channelsArray[indexChannel]);
        SnifferStart(handle);
        indexChannel++;
        if (indexChannel == channelsNumber)
        {
            indexChannel = 0;
            indexLoop++;
        }
        //printf("Control variabile: Index canale:%d Numar Canale:%d Break Loop:%d Index Loop:%d\n",indexChannel,channelsNumber,breakwhileloop,indexLoop);
    }
    SnifferClose(handle);
    printf("Numarul de pachete analizate este:%d\n", cap_packet_counter);
    return 0;
}