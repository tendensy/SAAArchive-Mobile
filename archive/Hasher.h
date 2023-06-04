#pragma once
#include "CryptoContext.h"

#include <stdio.h>
#include <stdlib.h>
#include "../util/armhook.h"
#include "../game/common.h"

class CHasher
{
private:
	static uint32_t ms_dwHashAlgorithm;
	
	uint32_t m_hCryptHash;
	CCryptoContext* m_pContext;

public:
	CHasher(CCryptoContext* pContext);
	~CHasher(void);

	void AddData(uint32_t dwDataLength, uint8_t* pbData);
	void GetContainer();

};
