#pragma once
#include "CryptoContext.h"

#include <stdio.h>
#include <stdlib.h>
#include "../util/armhook.h"
#include "../game/common.h"

class CKeyPair
{
private:
	static uint32_t ms_dwRSAKeySize;

	char* m_hCryptKey;
	CCryptoContext* m_pContext;

public:
	CKeyPair(CCryptoContext* pContext);
	~CKeyPair(void);
	
#ifdef ARCTOOL
	void GenerateKey();
	void LoadFromFile(char* szFileName);
	void WriteToFile(char* szFileName);
	void WriteCHeaderFile(char* szFileName);
#endif

	void LoadFromMemory(uint32_t dwPubKeySize, uint8_t* pbPubKeyBlob, uint8_t bytXORKey);
	void ReleaseKey();	

	void GetContainer();
};
