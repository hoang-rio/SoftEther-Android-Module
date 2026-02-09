/**
 * Bridge stub for Android - Minimal implementation
 * This provides stub functions needed by Connection.c and Hub.c
 */

#include "stubs.h"

// Stub implementations for bridge functions
bool IsBridgeSupported(void)
{
    return false;
}

bool IsNeedWinPcap(void)
{
    return false;
}

bool IsEthSupported(void)
{
    return false;
}

void *GetEthList(void)
{
    return NULL;
}

void FreeEth(ETH *e)
{
    (void)e;
}

bool InitEth(void)
{
    return false;
}

void FreeEthList(void *t)
{
    if (t != NULL)
    {
        // FreeToken(t);
    }
}

ETH *OpenEth(char *name, bool local, bool promisc_mode, bool jumbo_packet)
{
    (void)name;
    (void)local;
    (void)promisc_mode;
    (void)jumbo_packet;
    return NULL;
}

void CloseEth(ETH *e)
{
    (void)e;
}

void *EthGetCancel(ETH *e)
{
    (void)e;
    return NULL;
}

UINT EthGetPacket(ETH *e, void **data)
{
    (void)e;
    (void)data;
    return 0;
}

void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes)
{
    (void)e;
    (void)num;
    (void)datas;
    (void)sizes;
}

void EthPutPacket(ETH *e, void *data, UINT size)
{
    (void)e;
    (void)size;
    if (data != NULL)
    {
        // Free(data);
    }
}

bool EthIsLocalBridge(ETH *e)
{
    (void)e;
    return false;
}

UINT EthGetMtu(ETH *e)
{
    (void)e;
    return 0;
}

// Bridge functions
BRIDGE *BrNewBridge(void *h, char *name, void *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast, LOCALBRIDGE *parent_local_bridge)
{
    (void)h;
    (void)name;
    (void)p;
    (void)local;
    (void)monitor;
    (void)tapmode;
    (void)tapaddr;
    (void)limit_broadcast;
    (void)parent_local_bridge;
    return NULL;
}

void BrFreeBridge(BRIDGE *b)
{
    (void)b;
}

void BrBridgeProc(void *t, void *param)
{
    (void)t;
    (void)param;
}

void InitBridge(void)
{
}

void FreeBridge(void)
{
}

void InitLocalBridgeList(void *c)
{
    (void)c;
}

void FreeLocalBridgeList(void *c)
{
    (void)c;
}

void AddLocalBridge(void *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast)
{
    (void)c;
    (void)hubname;
    (void)devicename;
    (void)local;
    (void)monitor;
    (void)tapmode;
    (void)tapaddr;
    (void)limit_broadcast;
}

void DelLocalBridge(void *c, LOCALBRIDGE *b)
{
    (void)c;
    (void)b;
}

LOCALBRIDGE *FindLocalBridge(void *c, char *hubname, char *devicename)
{
    (void)c;
    (void)hubname;
    (void)devicename;
    return NULL;
}

void StartLocalBridge(LOCALBRIDGE *b)
{
    (void)b;
}

void StopLocalBridge(LOCALBRIDGE *b)
{
    (void)b;
}

void FreeLocalBridge(LOCALBRIDGE *b)
{
    (void)b;
}

LOCALBRIDGE *EnumLocalBridge(void *c, UINT id)
{
    (void)c;
    (void)id;
    return NULL;
}

void StopAllLocalBridge(void *c)
{
    (void)c;
}

void SetLocalBridgePriority(LOCALBRIDGE *b, UINT priority)
{
    (void)b;
    (void)priority;
}

// Microsoft adapter functions (Windows-specific)
void *MsCreateAdapterListEx(bool include_hidden)
{
    (void)include_hidden;
    return NULL;
}

void MsFreeAdapterList(void *list)
{
    (void)list;
}

// VLAN functions
VLAN *NewVLAN(char *instance_name, VLAN_PARAM *param)
{
    (void)instance_name;
    (void)param;
    return NULL;
}

void FreeVLAN(VLAN *v)
{
    (void)v;
}

void *VLANGetCancel(VLAN *v)
{
    (void)v;
    return NULL;
}

bool VLANGetNextPacket(VLAN *v, void **data)
{
    (void)v;
    (void)data;
    return false;
}

void VLANPutPacket(VLAN *v, void *data, UINT size)
{
    (void)v;
    (void)size;
    if (data != NULL)
    {
        // Free(data);
    }
}

bool VLANSetStatus(VLAN *v, VLAN_PARAM *param)
{
    (void)v;
    (void)param;
    return false;
}

// Layer 2 bridge functions
void BrSetEnumMacAddressListProc(BRIDGE *b, void *proc)
{
    (void)b;
    (void)proc;
}

void BrSetEnumLocalIPProc(BRIDGE *b, void *proc)
{
    (void)b;
    (void)proc;
}
