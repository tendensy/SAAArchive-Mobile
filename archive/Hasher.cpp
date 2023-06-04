#include "Hasher.h"
#include "CryptoFns.h"

//------------------------------------

//uint32_t CHasher::ms_dwHashAlgorithm = nullptr;

//------------------------------------

CHasher::CHasher(CCryptoContext* pContext)
{
	// Save context for later
	m_pContext = pContext;

	// Generate a hash container
	//uint32_t hCryptProv = pContext->GetProvider();
	//crypt(CreateHash)(hCryptProv, ms_dwHashAlgorithm, nullptr, nullptr, &m_hCryptHash);

}

//------------------------------------

CHasher::~CHasher(void)
{
	// Destory the hash container
	//crypt(DestroyHash)(m_hCryptHash);
}


//------------------------------------

void CHasher::AddData(uint32_t dwDataLength, uint8_t *pbData)
{
	// Add the data to be hashed
//	crypt(HashData)(m_hCryptHash, pbData, dwDataLength, 0);
}

//------------------------------------

void CHasher::GetContainer()
{
	//return m_hCryptHash;
}


//------------------------------------
