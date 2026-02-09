/**
 * Virtual stub for Android - Minimal implementation
 * This provides stub functions for virtual adapter operations
 */

#include "stubs.h"
#include <Cedar/Cedar.h>
#include <Cedar/Virtual.h>
#include <Cedar/IPC.h>

// Virtual LAN card functions
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param)
{
    (void)instance_name;
    (void)param;
    return NULL;
}

void FreeVLan(VLAN *v)
{
    (void)v;
}

void *VLanGetCancel(VLAN *v)
{
    (void)v;
    return NULL;
}

bool VLanGetNextPacket(VLAN *v, void **data)
{
    (void)v;
    (void)data;
    return false;
}

void VLanPutPacket(VLAN *v, void *data, UINT size)
{
    (void)v;
    (void)size;
    if (data != NULL)
    {
        Free(data);
    }
}

UINT VLanGetPacket(VLAN *v, void **data)
{
    (void)v;
    (void)data;
    return 0;
}

void VLanPutPackets(VLAN *v, UINT num, void **datas, UINT *sizes)
{
    (void)v;
    (void)num;
    (void)datas;
    (void)sizes;
}

bool VLanSetStatus(VLAN *v, VLAN_PARAM *param)
{
    (void)v;
    (void)param;
    return false;
}

// Virtual interface functions
VIRTUAL *NewVirtual(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, ACCOUNT *account)
{
    (void)cedar;
    (void)option;
    (void)auth;
    (void)pa;
    (void)account;
    return NULL;
}

void FreeVirtual(VIRTUAL *v)
{
    (void)v;
}

void VirtualInit(VIRTUAL *v)
{
    (void)v;
}

void VirtualFree(VIRTUAL *v)
{
    (void)v;
}

void VirtualThread(THREAD *t, void *param)
{
    (void)t;
    (void)param;
}

void VirtualListenerThread(THREAD *t, void *param)
{
    (void)t;
    (void)param;
}

// IPC virtual functions
IPC *NewIPCVirtual(CEDAR *cedar, char *server_name, char *hub_name, char *user_name, char *password,
                   UINT *error_code, char *client_str, UINT client_ver, UINT client_build,
                   char *client_info, UCHAR *unique_id, IP *client_ip, UINT client_port,
                   IP *server_ip, UINT server_port, char *crypt_name, bool bridge_mode,
                   UINT mss, bool is_layer3)
{
    (void)cedar;
    (void)server_name;
    (void)hub_name;
    (void)user_name;
    (void)password;
    (void)error_code;
    (void)client_str;
    (void)client_ver;
    (void)client_build;
    (void)client_info;
    (void)unique_id;
    (void)client_ip;
    (void)client_port;
    (void)server_ip;
    (void)server_port;
    (void)crypt_name;
    (void)bridge_mode;
    (void)mss;
    (void)is_layer3;
    return NULL;
}

void FreeIPCVirtual(IPC *ipc)
{
    (void)ipc;
}

void IPCVirtualThread(THREAD *t, void *param)
{
    (void)t;
    (void)param;
}

// Layer 3 functions
L3SW *NewL3Sw(CEDAR *cedar, char *name)
{
    (void)cedar;
    (void)name;
    return NULL;
}

void FreeL3Sw(L3SW *s)
{
    (void)s;
}

void L3SwThread(THREAD *t, void *param)
{
    (void)t;
    (void)param;
}

L3IF *L3AddIf(L3SW *s, char *hub_name, UINT ip, UINT subnet)
{
    (void)s;
    (void)hub_name;
    (void)ip;
    (void)subnet;
    return NULL;
}

void L3DelIf(L3SW *s, UINT ip)
{
    (void)s;
    (void)ip;
}

L3TABLE *L3AddTable(L3SW *s, UINT network, UINT subnet, UINT gateway, UINT metric)
{
    (void)s;
    (void)network;
    (void)subnet;
    (void)gateway;
    (void)metric;
    return NULL;
}

void L3DelTable(L3SW *s, UINT network, UINT subnet)
{
    (void)s;
    (void)network;
    (void)subnet;
}

L3ARPENTRY *L3AddArp(L3SW *s, UINT ip, UCHAR *mac)
{
    (void)s;
    (void)ip;
    (void)mac;
    return NULL;
}

void L3DelArp(L3SW *s, UINT ip)
{
    (void)s;
    (void)ip;
}

// Null LAN functions
NULL_LAN *NewNullLan(char *name)
{
    (void)name;
    return NULL;
}

void FreeNullLan(NULL_LAN *n)
{
    (void)n;
}

void *NullLanGetCancel(NULL_LAN *n)
{
    (void)n;
    return NULL;
}

UINT NullLanGetPacket(NULL_LAN *n, void **data)
{
    (void)n;
    (void)data;
    return 0;
}

void NullLanPutPacket(NULL_LAN *n, void *data, UINT size)
{
    (void)n;
    (void)size;
    if (data != NULL)
    {
        Free(data);
    }
}

// Get VLAN list
TOKEN_LIST *EnumVLan(char *tag_name)
{
    (void)tag_name;
    return NewTokenList();
}

// VLAN tag - not used on Android
char *GetVLanTag(char *name)
{
    (void)name;
    return NULL;
}

// Get VLAN interface name
char *GetVLanInterfaceName(char *name)
{
    (void)name;
    return NULL;
}

// Check if VLAN exists
bool IsVLan(char *name)
{
    (void)name;
    return false;
}

// Unix VLAN list operations
UNIX_VLAN_LIST *UnixVLanNewList()
{
    return NULL;
}

void UnixVLanFreeList(UNIX_VLAN_LIST *list)
{
    (void)list;
}

void UnixVLanAdd(UNIX_VLAN_LIST *list, char *name, UCHAR *mac, bool up)
{
    (void)list;
    (void)name;
    (void)mac;
    (void)up;
}

void UnixVLanDel(UNIX_VLAN_LIST *list, char *name)
{
    (void)list;
    (void)name;
}

UNIX_VLAN *UnixVLanGet(UNIX_VLAN_LIST *list, char *name)
{
    (void)list;
    (void)name;
    return NULL;
}

TOKEN_LIST *UnixVLanEnum()
{
    return NewTokenList();
}

bool UnixVLanCreate(char *name, UCHAR *mac_address, bool up)
{
    (void)name;
    (void)mac_address;
    (void)up;
    return true;
}

bool UnixVLanDelete(char *name)
{
    (void)name;
    return true;
}

bool UnixVLanSetState(char *name, bool up)
{
    (void)name;
    (void)up;
    return true;
}

void UnixVLanInit()
{
}

void UnixVLanFree()
{
}

// Unix VLAN tag
char *UnixGetVLanTag(char *name)
{
    (void)name;
    return NULL;
}
