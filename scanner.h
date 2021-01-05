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

const char* fc_type = {"Management","Control","Data","Extension"};

