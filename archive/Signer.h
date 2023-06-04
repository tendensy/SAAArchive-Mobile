#pragma once
#include "Hasher.h"
#include "KeyPair.h"

#include <stdio.h>
#include <stdlib.h>
#include "../main.h"
#include "../util/armhook.h"
#include "../game/common.h"

class CSigner
{
private:
	uint8_t* m_pbSignature;
	uint32_t m_dwLength;

public:
	CSigner(void);
	~CSigner(void);

#ifdef ARCTOOL
	void SignHash(CHasher* pHasher);
	uint8_t* GetSignature();
	uint32_t GetSignatureLength();
#endif

	void SetSignature(uint32_t dwLength, uint8_t* pbSignature);
	bool VerifySignature(CHasher* pHasher, CKeyPair* pKeyPair);

};
