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
struct raw_data {
    char frameType[16];
    char frameSubtype[16];
    int direction;
	int channel;
	int apChannel;
    char da[13];
    char sa[13];
	char bs[13];
	char ssid[32];
	char summaryHash[45];
	int rssi;
} raw_data;

pcap_t *handle;
raw_data *rd;
char *adapter = (char *)"mon0"; //placa wireless in mod monitorizare
int maxIndexLoop;               // numarul maxim de scanari
int scanningTime;               // periaoada de scanare pentru un canal, in secunde
int *channelsArray;             //lista canalelor suportate
int channelsNumber;             //numarul de canale suportate
int currentChannel;             //canalul pe care este setata placa wireless
int cap_packet_counter = 0;     //numarul de pachete capturate
int breakwhileloop = 1;         //folosit la intreruperea buclei while din main()
