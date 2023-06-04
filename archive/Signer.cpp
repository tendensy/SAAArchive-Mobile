#include "Signer.h"
#include "CryptoFns.h"

CSigner::CSigner(void)
{
	m_dwLength = 0;
	m_pbSignature = nullptr;
}

//------------------------------------

CSigner::~CSigner(void)
{
	if (m_pbSignature != nullptr)
		delete[] m_pbSignature;
}

//------------------------------------

#ifdef ARCTOOL
void CSigner::SignHash(CHasher *pHasher) 
{
	if (m_pbSignature != nullptr)
		delete[] m_pbSignature;

	CryptSignHash(pHasher->GetContainer(), AT_SIGNATURE, nullptr, CRYPT_NOHASHOID, nullptr, &m_dwLength);
	m_pbSignature = new uint8_t[m_dwLength];
	CryptSignHash(pHasher->GetContainer(), AT_SIGNATURE, nullptr, CRYPT_NOHASHOID, m_pbSignature, &m_dwLength);

}
#endif

//------------------------------------

#ifdef ARCTOOL
uint8_t* CSigner::GetSignature()
{
	return m_pbSignature;
}
#endif

//------------------------------------

#ifdef ARCTOOL
uint8_t CSigner::GetSignatureLength()
{
	return m_dwLength;
}
#endif

//------------------------------------

void CSigner::SetSignature(uint32_t dwLength, uint8_t *pbSignature)
{
	if (m_pbSignature != nullptr)
		delete[] m_pbSignature;

	m_dwLength = dwLength;
	m_pbSignature = new uint8_t[dwLength];
	memcpy(m_pbSignature, pbSignature, m_dwLength);
}

//------------------------------------

bool CSigner::VerifySignature(CHasher *pHasher, CKeyPair *pKeyPair)
{
	bool bVerify;

	//bVerify = crypt(VerifySignature)(pHasher->GetContainer(), m_pbSignature, m_dwLength, pKeyPair->GetContainer(), nullptr, nullptr);

	return bVerify;
}

//------------------------------------
