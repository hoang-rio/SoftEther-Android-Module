/**
 * Bridge stub for Android - Minimal implementation
 * This provides stub functions for bridge operations that are not needed on Android
 */

#include "stubs.h"
#include <Cedar/Cedar.h>
#include <Cedar/Bridge.h>

// Check if bridge is supported
bool IsBridgeSupported()
{
    return false;
}

bool IsNeedWinPcap()
{
    return false;
}

bool IsRawIpBridgeSupported()
{
    return false;
}

UINT GetEthDeviceHash()
{
    return 0;
}

// Bridge functions
BRIDGE *BrNewBridge(HUB *h, char *name, POLICY *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast, LOCALBRIDGE *parent_local_bridge)
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

void BrBridgeThread(THREAD *thread, void *param)
{
    (void)thread;
    (void)param;
}

void InitLocalBridgeList(CEDAR *c)
{
    (void)c;
}

void FreeLocalBridgeList(CEDAR *c)
{
    (void)c;
}

void AddLocalBridge(CEDAR *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast)
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

bool DeleteLocalBridge(CEDAR *c, char *hubname, char *devicename)
{
    (void)c;
    (void)hubname;
    (void)devicename;
    return false;
}
