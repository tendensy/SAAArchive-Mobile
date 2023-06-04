#include "KeyPair.h"
#include "CryptoFns.h"
#include <stdio.h>

//------------------------------------
uint32_t CKeyPair::ms_dwRSAKeySize = 1024;

//------------------------------------

CKeyPair::CKeyPair(CCryptoContext* pContext)
{
	m_pContext = pContext;
	m_hCryptKey = nullptr;
}

//------------------------------------

CKeyPair::~CKeyPair(void)
{
	if(m_hCryptKey != nullptr)
		ReleaseKey();
}

//------------------------------------

#ifdef ARCTOOL
void CKeyPair::GenerateKey() 
{
	// Generate a key pair
	// HCRYPTPROV hCryptProv = m_pContext->GetProvider();
	CryptGenKey(m_pContext->GetProvider(), AT_SIGNATURE, (ms_dwRSAKeySize << 16) | CRYPT_EXPORTABLE, &m_hCryptKey);
}
#endif

//------------------------------------

void CKeyPair::ReleaseKey() 
{
	// Destroy the key pair
	m_hCryptKey = nullptr;
	//crypt(DestroyKey)(m_hCryptKey);
}

//------------------------------------

#ifdef ARCTOOL
void CKeyPair::LoadFromFile(char* szFileName) 
{
	uint32_t dwKeySize;
	uint8_t *pbKeyBlob;
	FILE *fiKey;

	// Load the private key from a file
	fopen_s(&fiKey, (char*)szFileName, "rb");
	fread(&dwKeySize, sizeof(dwKeySize), 1, fiKey);
	pbKeyBlob = new uint8_t[dwKeySize];
	fread(pbKeyBlob, 1, dwKeySize, fiKey);
	fclose(fiKey);

	// Load the key pair
	// HCRYPTPROV hCryptProv = m_pContext->GetProvider();
	CryptImportKey(m_pContext->GetProvider(), pbKeyBlob, dwKeySize, nullptr, CRYPT_EXPORTABLE, &m_hCryptKey);

	// Clean up memory
	delete[] pbKeyBlob;

}
#endif

//------------------------------------

#ifdef ARCTOOL
void CKeyPair::WriteToFile(char* szFileName) 
{
	uint32_t dwKeySize;
	uint8_t *pbKeyBlob;
	FILE *fiKey;

	// Export the private key
	CryptExportKey(m_hCryptKey, nullptr, PRIVATEKEYBLOB, 0, nullptr, &dwKeySize);
	pbKeyBlob = new uint8_t[dwKeySize];
	CryptExportKey(m_hCryptKey, nullptr, PRIVATEKEYBLOB, 0, pbKeyBlob, &dwKeySize);
	
	// Write the private key to a file
	fopen_s(&fiKey, (char*)szFileName, "wb");
	fwrite(&dwKeySize, sizeof(dwKeySize), 1, fiKey);
	fwrite(pbKeyBlob, 1, dwKeySize, fiKey);
	fclose(fiKey);

	// Clean up memory
	delete[] pbKeyBlob;

}
#endif

//------------------------------------

#ifdef ARCTOOL
void CKeyPair::WriteCHeaderFile(char* szFileName)
{

	const uint8_t bytXORKey = 0xAA;
	uint32_t dwKeySize;
	uint8_t *pbKeyBlob;
	FILE *fiHeader;

	// Export the public key
	CryptExportKey(m_hCryptKey, nullptr, PUBLICKEYBLOB, 0, nullptr, &dwKeySize);
	pbKeyBlob = new uint8_t[dwKeySize];
	CryptExportKey(m_hCryptKey, nullptr, PUBLICKEYBLOB, 0, pbKeyBlob, &dwKeySize);

	// Generate the header file
	fopen_s(&fiHeader, szFileName, "wt");
	fclose(fiHeader);

	// Clean up
	delete[] pbKeyBlob;

}
#endif

//------------------------------------

void CKeyPair::LoadFromMemory(uint32_t dwPubKeySize, uint8_t* pbPubKeyBlob, uint8_t bytXORKey)
{
	uint8_t *pbKeyBlob;

	// Un-XOR keys from memory
	if (bytXORKey != 0) {
		pbKeyBlob = new uint8_t[dwPubKeySize];
		for(uint32_t i=0; i<dwPubKeySize; i++)
			pbKeyBlob[i] = pbPubKeyBlob[i] ^ bytXORKey;
	} else {
		pbKeyBlob = pbPubKeyBlob;
	}

	// Import the key
	//HCRYPTPROV hCryptProv = m_pContext->GetProvider();
//	crypt(ImportKey)(m_pContext->GetProvider(), pbKeyBlob, dwPubKeySize, nullptr, nullptr, &m_hCryptKey);

	// Clean up
	if (bytXORKey != 0) {
		delete[] pbKeyBlob;
	}

}

//------------------------------------

void CKeyPair::GetContainer() 
{
//	return m_hCryptKey;
}

//------------------------------------
