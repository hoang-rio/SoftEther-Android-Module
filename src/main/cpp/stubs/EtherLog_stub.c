/**
 * EtherLog stub for Android - Minimal implementation
 * This provides stub functions for Ethernet logging
 */

#include "../SoftEtherVPN/src/Cedar/Cedar.h"
#include "../SoftEtherVPN/src/Cedar/EtherLog.h"
#include "../SoftEtherVPN/src/Mayaqua/Mayaqua.h"

// Stub implementations for EtherLog functions
void InitEtherLog()
{
}

void FreeEtherLog()
{
}

ETHERSNMPLOG *NewESL()
{
    return NULL;
}

void FreeESL(ETHERSNMPLOG *esl)
{
}

void EslLog(ETHERSNMPLOG *esl, char *str)
{
}

void EslLogMain(ETHERSNMPLOG *esl)
{
}

bool EslIsEnabled(ETHERSNMPLOG *esl)
{
    return false;
}

void EslSetEnabled(ETHERSNMPLOG *esl, bool enabled)
{
}

void EslPoller(ETHERSNMPLOG *esl)
{
}

void EslAdd(ETHERSNMPLOG *esl, ETHERIP *ip)
{
    if (ip != NULL)
    {
        Free(ip);
    }
}

void EslAddIpPacket(ETHERSNMPLOG *esl, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void EslUdpSend(ETHERSNMPLOG *esl, void *data, UINT size, IP *dest_ip, UINT dest_port)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void EslUdpRecv(ETHERSNMPLOG *esl)
{
}

void EslSend(ETHERSNMPLOG *esl, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

UINT EslGetNextTtl(ETHERSNMPLOG *esl)
{
    return 0;
}

// Helper functions
UINT GetNumActiveEtherLog(HUB *h)
{
    return 0;
}

bool CanCreateNewEtherLog(HUB *h)
{
    return false;
}

void StartEtherLog(HUB *h)
{
}

void StopEtherLog(HUB *h)
{
}

void EtherLogMain(THREAD *t, void *param)
{
}

void EtherLogThread(THREAD *t, void *param)
{
}

bool IsEtherLogEnabled(HUB *h)
{
    return false;
}

void SetEtherLogEnabled(HUB *h, bool enabled)
{
}

void AddEtherLog(HUB *h, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void AddEtherLogIpPacket(HUB *h, void *data, UINT size)
{
    if (data != NULL)
    {
        Free(data);
    }
}

void EtherLogProc(HUB *h)
{
}

void EtherLogInit(HUB *h)
{
}

void EtherLogFree(HUB *h)
{
}

bool EtherLogGetSetting(HUB *h, ETHERSNMPLOG *setting)
{
    return false;
}

bool EtherLogSetSetting(HUB *h, ETHERSNMPLOG *setting)
{
    return false;
}
