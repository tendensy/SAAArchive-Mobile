#include "CryptoContext.h"
#include "CryptoFns.h"

#include <stdio.h>
#include <stdlib.h>
#include "../util/armhook.h"
#include "../game/common.h"

//------------------------------------

char* CCryptoContext::ms_szProviderName = nullptr;
char* CCryptoContext::ms_szContainerName = (char*)"SAMP";

//------------------------------------

CCryptoContext::CCryptoContext(void)
{
//	ms_dwRefCount++;
}

//------------------------------------

CCryptoContext::~CCryptoContext(void)
{
	

}

//------------------------------------

#ifdef ARCTOOL
void CCryptoContext::GenerateRandom(uint32_t dwLength, uint8_t* pbBuffer) 
{
	CryptGenRandom(m_hCryptProv, dwLength, pbBuffer);
}
#endif
