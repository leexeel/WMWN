#include <pcap/pcap.h>

struct mgmt_header_t
{
    uint8_t fc[2];     /* 2 bytes */
    uint16_t duration; /* 2 bytes */
    uint8_t da[6];     /* 6 bytes */
    uint8_t sa[6];     /* 6 bytes */
    uint8_t bssid[6];  /* 6 bytes */
    uint16_t seq_ctrl; /* 2 bytes */
};


struct mgmt_header_t_adhoc
{
    uint8_t fc[2];     /* 2 bytes */
    uint16_t duration; /* 2 bytes */
    uint8_t da[6];     /* 6 bytes */
    uint8_t sa[6];     /* 6 bytes */
    uint8_t bssid[6];  /* 6 bytes */
    uint16_t seq_ctrl; /* 2 bytes */
    uint8_t ra[6];     /* 2 bytes */
};

enum ieee80211_frame_type
{
    Management = 0,
    Control = 1,
    Data = 2,
    Extension = 3
};

enum ieee80211_management_subtype
{
    AssociationRequest = 0,
    AssociationResponse = 1,
    ReassociationRequest = 2,
    ReassociationResponse = 3,
    ProbeRequest = 4,
    ProbeResponse = 5,
    TimingAdvertisement = 6,
    Reserved1 = 7,
    Beacon = 8,
    Atim = 9,
    Disassociation = 10,
    Authentication = 11,
    Deauthentication = 12,
    Action = 13,
    ActionNoAck = 14,
    Reserved2 = 15
};

/*
To DS and From DS are both 0

Address 1 = Destination
Address 2 = Source
Address 3 = BSSID

To DS field is 1 and From DS field is 0

Address 1 = BSSID
Address 2 = Source
Address 3 = Destination

To DS field is 0 and From DS field is 1

Address 1 = Destination
Address 2 = BSSID
Address 3 = Source

To DS and From DS are both 1

Address 1 = Receiver
Address 2 = Transmitter
Address 3 = Destination
Address 4 = Source
*/

enum FromToDS
{
    Adhoc = 0,
    FromDS = 1,
    ToDS = 2,
    WDS = 3
};

struct raw_data {
    char frameType[16];
    char frameSubtype[16];
    int direction;
	int channel;
	int apChannel;
    char da[19];
    char sa[19];
	char bs[19];
	char ssid[32];
	char summaryHash[45];
	int rssi;
    int apChannel2;
} raw_data;

pcap_t *handle;
struct raw_data rd;
char *adapter = (char *)"mon0"; //placa wireless in mod monitorizare
int maxIndexLoop;               // numarul maxim de scanari
int scanningTime;               // periaoada de scanare pentru un canal, in secunde
int *channelsArray;             //lista canalelor suportate
int channelsNumber;             //numarul de canale suportate
int currentChannel;             //canalul pe care este setata placa wireless
int cap_packet_counter = 0;     //numarul de pachete capturate
int breakwhileloop = 1;         //folosit la intreruperea buclei while din main()
int direction;                  //valorile ToDS/FromDS
int doNotRecord = 0;            // daca este 1 atunci nu se inregistreaza in BD