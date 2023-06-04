#include "TinyEncrypt.h"
#include "Obfuscator.h"
#include <stdio.h>

//------------------------------------

uint32_t CTinyEncrypt::ms_dwRounds = 32;
uint32_t CTinyEncrypt::ms_dwInitDelta = OBFUSCATE_DATA(0x9E3779B9);
uint32_t CTinyEncrypt::ms_dwInitSum = 0;
bool  CTinyEncrypt::ms_bInitDone = false;

//------------------------------------

CTinyEncrypt::CTinyEncrypt(void)
{
	if (!ms_bInitDone) {
		ms_dwInitDelta = UNOBFUSCATE_DATA(ms_dwInitDelta);
		ms_dwInitSum = ms_dwInitDelta * ms_dwRounds;
		ms_bInitDone = true;
	}
}

//------------------------------------

CTinyEncrypt::~CTinyEncrypt(void)
{
}

//------------------------------------

void CTinyEncrypt::SetKey(uint8_t *pbKey, uint8_t bytXORKey)
{
	memcpy(m_pdwKey, pbKey, TEA_KEY_SIZE);

	if (bytXORKey != 0) 
	{
		uint8_t *pbKeyRef = reinterpret_cast<uint8_t*>(m_pdwKey);
		for(uint32_t i=0; i<TEA_KEY_SIZE; i++)
			pbKeyRef[i] ^= bytXORKey;
	}
	
}

//------------------------------------

#ifdef ARCTOOL

void CTinyEncrypt::EncryptBlock(uint32_t &dwV0, uint32_t &dwV1)
{
	uint32_t dwSum = 0;
	
	for(uint32_t i=0; i<ms_dwRounds; i++) {
		dwV0 += ((dwV1 << 4 ^ dwV1 >> 5) + dwV1) ^ (dwSum + m_pdwKey[dwSum & 3]);
		dwSum += ms_dwInitDelta;
		dwV1 += ((dwV0 << 4 ^ dwV0 >> 5) + dwV0) ^ (dwSum + m_pdwKey[dwSum>>11 & 3]);
	}

	m_pdwKey[0] ^= dwV0;
	m_pdwKey[1] ^= dwV1;
	m_pdwKey[2] ^= dwV0;
	m_pdwKey[3] ^= dwV1;

}
#endif

//------------------------------------

void CTinyEncrypt::DecryptBlock(uint32_t &dwV0, uint32_t &dwV1)
{
	uint32_t dwSum = ms_dwInitSum;

	uint32_t dwV0old = dwV0;
	uint32_t dwV1old = dwV1;

    for(uint32_t i=0; i<ms_dwRounds; i++) {
        dwV1 -= ((dwV0 << 4 ^ dwV0 >> 5) + dwV0) ^ (dwSum + m_pdwKey[dwSum>>11 & 3]);
        dwSum -= ms_dwInitDelta;
        dwV0 -= ((dwV1 << 4 ^ dwV1 >> 5) + dwV1) ^ (dwSum + m_pdwKey[dwSum & 3]);
    }

	m_pdwKey[0] ^= dwV0old;
	m_pdwKey[1] ^= dwV1old;
	m_pdwKey[2] ^= dwV0old;
	m_pdwKey[3] ^= dwV1old;

}

//------------------------------------

#ifdef ARCTOOL
void CTinyEncrypt::EncryptData(uint32_t dwLength, uint8_t *pbData)
{
	uint32_t dwBlocks = dwLength / 4;
	uint32_t *pdwData = reinterpret_cast<uint32_t*>(pbData);
	for(uint32_t i=0; i<dwBlocks; i+=2) {
		EncryptBlock(pdwData[i+0], pdwData[i+1]);
	}
}
#endif

//------------------------------------

void CTinyEncrypt::DecryptData(uint32_t dwLength, uint8_t *pbData)
{
	uint32_t dwBlocks = dwLength / 4;
	uint32_t *pdwData = reinterpret_cast<uint32_t*>(pbData);
	for(uint32_t i=0; i<dwBlocks; i+=2) {
		DecryptBlock(pdwData[i+0], pdwData[i+1]);
	}
}

//------------------------------------

#ifdef ARCTOOL
void CTinyEncrypt::LoadKey(char* szFileName)
{
	FILE* fiKey;

	fopen_s(&fiKey, (char*)szFileName, "rb");
	fread(m_pdwKey, 1, TEA_KEY_SIZE, fiKey);
	fclose(fiKey);
}
#endif

//------------------------------------

#ifdef ARCTOOL
void CTinyEncrypt::WriteKey(char* szFileName)
{
	FILE* fiKey;

	fopen_s(&fiKey, (char*)szFileName, "wb");
	fwrite(m_pdwKey, 1, TEA_KEY_SIZE, fiKey);
	fclose(fiKey);
}
#endif

//------------------------------------

#ifdef ARCTOOL
void CTinyEncrypt::WriteCHeaderFile(char* szFileName)
{

	const uint8_t bytXORKey = 0xAA;
	uint8_t* pbKey = reinterpret_cast<uint8_t*>(m_pdwKey);
	FILE *fiHeader;

}
#endif