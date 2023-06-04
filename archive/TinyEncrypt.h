#pragma once

#define TEA_KEY_SIZE		16

#include <stdlib.h>
#include <stdio.h>
#include "../util/armhook.h"
#include "../game/common.h"

class CTinyEncrypt
{
private:
	static uint32_t ms_dwRounds;
	static uint32_t ms_dwInitDelta;
	static uint32_t ms_dwInitSum;
	static bool ms_bInitDone;

	uint32_t m_pdwKey[TEA_KEY_SIZE/sizeof(uint32_t)];

#ifdef ARCTOOL
	void EncryptBlock(uint32_t &dwV0, uint32_t &dwV1);
#endif

	void DecryptBlock(uint32_t &dwV0, uint32_t &dwV1);

public:
	CTinyEncrypt(void);
	~CTinyEncrypt(void);

	void SetKey(uint8_t* pbKey, uint8_t bytXORKey);

#ifdef ARCTOOL
	void LoadKey(char* szFileName);
	void WriteKey(char* szFileName);
	void WriteCHeaderFile(char* szFileName);

	void EncryptData(uint32_t dwLength, uint8_t* pbData);
#endif
	
	void DecryptData(uint32_t dwLength, uint8_t* pbData);
};
