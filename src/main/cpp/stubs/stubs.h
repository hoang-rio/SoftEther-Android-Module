/**
 * Stubs header for Android build
 * This must be included BEFORE any Cedar headers to provide structure definitions
 */

#ifndef STUBS_H
#define STUBS_H

#include "../SoftEtherVPN/src/Mayaqua/Mayaqua.h"

// Forward declarations
struct BRIDGE;
struct LOCALBRIDGE;
struct ETH;

// Constants (from Cedar.h)
#ifndef MAX_HUBNAME_LEN
#define MAX_HUBNAME_LEN 255
#endif

// Prevent Bridge.h from being processed
#ifndef BRIDGE_H
#define BRIDGE_H
#endif

// Define BRIDGE structure
struct BRIDGE
{
    bool Active;
    bool Halt;
    void *Hub;  // HUB *
    struct ETH *Eth;
    char Name[MAX_SIZE];
    void *Policy;  // POLICY *
    bool Local;
    bool Monitor;
    bool TapMode;
    UCHAR TapMacAddress[6];
    bool LimitBroadcast;
    struct LOCALBRIDGE *LocalBridge;
    void *Cancel;  // CANCEL *
    void *Lock;    // LOCK *
    void *Session; // SESSION *
    UINT64 LastBridgeTry;
    UINT64 LastBeaconHostSend;
    UINT64 LastBeaconHostCrc;
    bool BridgeIpNotGetExceeded;
    UINT BridgeIpNotGetNum;
    void *EnumMacAddressListProc;
    void *EnumLocalIPProc;
    bool IsWinPcap;
    bool IsSolaris;
    bool IsLinux;
    bool IsBSD;
    bool IsMacOs;
    UINT64 LastSetMtu;
    UINT CurrentMtu;
    // Additional fields used by Connection.c
    UINT64 LastNumDeviceCheck;
    UINT LastNumDevice;
    UINT64 LastChangeMtuError;
};

// Define LOCALBRIDGE structure (needed by Admin.c)
struct LOCALBRIDGE
{
    char DeviceName[MAX_SIZE];
    char HubName[MAX_HUBNAME_LEN + 1];
    bool TapMode;
    UCHAR TapMacAddress[6];
    bool LimitBroadcast;
    UINT Priority;
    bool Active;
    bool Online;
    bool BridgeIsPromiscuousMode;
    bool BridgeAlwaysSendArpResponse;
    struct BRIDGE *Bridge;
    void *Hub;     // HUB *
    void *Cedar;   // CEDAR *
    void *Lock;    // LOCK *
    UINT64 LastConnectErrorTime;
    bool Monitor;
    bool AutoDelete;
    UINT64 LastBridgeTry;
    void *Policy;  // POLICY *
    bool Local;
    struct LOCALBRIDGE *NextLocalBridge;
    struct LOCALBRIDGE *PrevLocalBridge;
};

// Define ETH structure
struct ETH
{
    char Name[MAX_SIZE];
    UINT64 SessionId;
    bool IsRawIpMode;
    bool IsNullMode;
    void *Sock;  // SOCK *
    UINT CurrentIpAddress;
    UINT CurrentSubnetMask;
    UINT CurrentMtu;
    bool IsLocalBridge;
    void *Sock2; // SOCK *
    bool IsLocalBridge_entity;
    bool Flag1;
    bool IsLoopback;
    bool HasSetMtu;
    bool HasSetMacAddress;
    UCHAR MacAddress[6];
    UCHAR Padding[2];
    bool IsOpenVPN;
    void *OpenVPN;
    void *Bridge;
    bool IsVpnOverIcmp;
    bool IsVpnOverDns;
    void *VpnOverDnsSock;     // SOCK *
    void *VpnOverIcmpSock;    // SOCK *
    void *VpnOverDnsUdpSock;  // SOCK *
    void *VpnOverIcmpUdpSock; // SOCK *
    UINT VpnOverDnsId;
    UINT VpnOverIcmpId;
    bool IsRawIpBridge;
};

// Type aliases for compatibility
typedef struct BRIDGE BRIDGE;
typedef struct LOCALBRIDGE LOCALBRIDGE;
typedef struct ETH ETH;

// Stub function declarations
bool IsBridgeSupported(void);
bool IsNeedWinPcap(void);
bool IsEthSupported(void);
void *GetEthList(void);  // TOKEN_LIST *
void FreeEth(ETH *e);
bool InitEth(void);
void FreeEthList(void *t);  // TOKEN_LIST *
ETH *OpenEth(char *name, bool local, bool promisc_mode, bool jumbo_packet);
void CloseEth(ETH *e);
void *EthGetCancel(ETH *e);  // CANCEL *
UINT EthGetPacket(ETH *e, void **data);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
void EthPutPacket(ETH *e, void *data, UINT size);
bool EthIsLocalBridge(ETH *e);
UINT EthGetMtu(ETH *e);

BRIDGE *BrNewBridge(void *h, char *name, void *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast, LOCALBRIDGE *parent_local_bridge);
void BrFreeBridge(BRIDGE *b);
void BrBridgeProc(void *t, void *param);  // THREAD *
void InitBridge(void);
void FreeBridge(void);
void InitLocalBridgeList(void *c);  // CEDAR *
void FreeLocalBridgeList(void *c);  // CEDAR *
void AddLocalBridge(void *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast);  // CEDAR *
void DelLocalBridge(void *c, LOCALBRIDGE *b);  // CEDAR *
LOCALBRIDGE *FindLocalBridge(void *c, char *hubname, char *devicename);  // CEDAR *
void StartLocalBridge(LOCALBRIDGE *b);
void StopLocalBridge(LOCALBRIDGE *b);
void FreeLocalBridge(LOCALBRIDGE *b);
LOCALBRIDGE *EnumLocalBridge(void *c, UINT id);  // CEDAR *
void StopAllLocalBridge(void *c);  // CEDAR *
void SetLocalBridgePriority(LOCALBRIDGE *b, UINT priority);

// Microsoft adapter functions
void *MsCreateAdapterListEx(bool include_hidden);  // MS_ADAPTER_LIST *
void MsFreeAdapterList(void *list);  // MS_ADAPTER_LIST *

// VLAN functions
typedef struct VLAN VLAN;
typedef struct VLAN_PARAM VLAN_PARAM;
VLAN *NewVLAN(char *instance_name, VLAN_PARAM *param);
void FreeVLAN(VLAN *v);
void *VLANGetCancel(VLAN *v);  // CANCEL *
bool VLANGetNextPacket(VLAN *v, void **data);
void VLANPutPacket(VLAN *v, void *data, UINT size);
bool VLANSetStatus(VLAN *v, VLAN_PARAM *param);

// Layer 2 bridge functions
void BrSetEnumMacAddressListProc(BRIDGE *b, void *proc);
void BrSetEnumLocalIPProc(BRIDGE *b, void *proc);

#endif // STUBS_H
