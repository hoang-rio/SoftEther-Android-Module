/**
 * NativeStack stub for Android - Minimal implementation
 * This provides stub functions for native stack operations
 */

#include "../SoftEtherVPN/src/Cedar/Cedar.h"
#include "../SoftEtherVPN/src/Cedar/NativeStack.h"
#include "../SoftEtherVPN/src/Mayaqua/Mayaqua.h"

// Stub implementations for NativeStack functions
void InitNativeStack()
{
}

void FreeNativeStack()
{
}

NATIVE_STACK *NewNativeStack(CEDAR *cedar, char *name, char *mac_address_seed)
{
    return NULL;
}

void FreeNativeStack(NATIVE_STACK *s)
{
}

void NativeStackMainThread(THREAD *t, void *param)
{
}

void NativeStackSendThread(THREAD *t, void *param)
{
}

void NativeStackRecvThread(THREAD *t, void *param)
{
}

bool NativeStackSendIpPacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
    return false;
}

bool NativeStackSendIpPacketAsync(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
    return false;
}

void NativeStackSetIpThread(NATIVE_STACK *s, IP_THREAD_PROC *proc, void *param)
{
}

void NativeStackSetIpThreadParam(NATIVE_STACK *s, void *param)
{
}

void NativeStackSetIpPacketRecvCallback(NATIVE_STACK *s, IP_PACKET_RECV_CALLBACK *cb, void *param)
{
}

void NativeStackSetIPsecVpnPacketRecvCallback(NATIVE_STACK *s, IP_PACKET_RECV_CALLBACK *cb, void *param)
{
}

void NativeStackAddIpPacketToQueue(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackIpThread(NATIVE_STACK *s)
{
}

void NativeStackIpThreadInner(NATIVE_STACK *s)
{
}

void NativeStackProcessIpPacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackProcessArpPacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackProcessDhcpPacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackProcessDhcpRequestPacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackProcessDhcpDiscoverPacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackProcessDhcpReleasePacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackProcessDhcpInformPacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackProcessDhcpDeclinePacket(NATIVE_STACK *s, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void NativeStackProcessDhcpPacketMain(NATIVE_STACK *s, DHCPV4_HEADER *dhcp, UINT dhcp_size, UINT tran_id, UINT dest_ip, UINT src_ip, UCHAR *mac_address, IP *ip_from_mac)
{
}

void NativeStackSetDhcpOption(NATIVE_STACK *s, DHCP_OPTION_LIST *opt)
{
}

void NativeStackDhcpThread(THREAD *t, void *param)
{
}

void NativeStackDhcpThreadInner(NATIVE_STACK *s)
{
}

void NativeStackSetDhcpConfig(NATIVE_STACK *s, DHCP_CONFIG *config)
{
}

void NativeStackGetDhcpConfig(NATIVE_STACK *s, DHCP_CONFIG *config)
{
    if (config != NULL)
    {
        Zero(config, sizeof(DHCP_CONFIG));
    }
}

bool NativeStackGetCurrentDhcpConfig(NATIVE_STACK *s, DHCP_CONFIG *config)
{
    if (config != NULL)
    {
        Zero(config, sizeof(DHCP_CONFIG));
    }
    return false;
}

void NativeStackDhcpConfigThread(THREAD *t, void *param)
{
}

void NativeStackDhcpConfigThreadInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadSendRequest(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadRecvResponse(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadTimeout(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadTimeoutInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadTimeoutMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadFree(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadFreeInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadFreeMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadInit(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadInitInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadInitMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadStart(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadStartInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadStartMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadStop(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadStopInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadStopMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadWait(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadWaitInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadWaitMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadSendPacket(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadSendPacketInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadSendPacketMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadRecvPacket(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadRecvPacketInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadRecvPacketMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacket(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketError(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketErrorInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketErrorMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketSuccess(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketSuccessInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketSuccessMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketTimeout(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketTimeoutInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketTimeoutMain(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketDone(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketDoneInner(NATIVE_STACK *s)
{
}

void NativeStackDhcpConfigThreadProcessPacketDoneMain(NATIVE_STACK *s)
{
}
