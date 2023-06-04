#include "ArchiveFS.h"

#include "CryptoContext.h"
#include "../main.h"

#include "KeyPair.h"
#include "Signer.h"
#include "Hasher.h"

#include "TinyEncrypt.h"
#include "Obfuscator.h"

#include "../util/armhook.h"

#ifndef ARCTOOL
#include "../main.h"
#endif

//------------------------------------

uint32_t CArchiveFS::ms_dwHashInit = OBFUSCATE_DATA(0x9E3779B9);

//------------------------------------

CArchiveFS::CArchiveFS(void)
{
	m_dwNumEntries = SAA_MAX_ENTRIES;
	m_bLoaded = false;
	m_bEntriesLoaded = false;
}

//------------------------------------

CArchiveFS::CArchiveFS(uint32_t dwNumEntries, uint32_t dwFDSize)
{
	m_dwNumEntries = dwNumEntries;
	m_bLoaded = false;
	m_bEntriesLoaded = false;

	m_Header.dwFakeDataSize = dwFDSize;
}

//------------------------------------

CArchiveFS::~CArchiveFS(void)
{
}

//------------------------------------

uint32_t CArchiveFS::HashString(char* szString) 
{
	// This is an implementation of the hash

#	define mix(a,b,c) \
	{ \
		a -= b; a -= c; a ^= (c>>13); \
		b -= c; b -= a; b ^= (a<<8); \
		c -= a; c -= b; c ^= (b>>13); \
		a -= b; a -= c; a ^= (c>>12);  \
		b -= c; b -= a; b ^= (a<<16); \
		c -= a; c -= b; c ^= (b>>5); \
		a -= b; a -= c; a ^= (c>>3);  \
		b -= c; b -= a; b ^= (a<<10); \
		c -= a; c -= b; c ^= (b>>15); \
	}
	
	register uint8_t* k = (uint8_t*)szString;
	register uint32_t initval = 0x12345678;
	register uint32_t length;

	length = (uint32_t)strlen(szString);
	
	register uint32_t a,b,c,len;

	/* Set up the internal state */
	len = length;
	a = b = ms_dwHashInit; /* the golden ratio; an arbitrary value */
	c = initval;         /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
	a += (k[0] +((uint32_t)k[1]<<8) +((uint32_t)k[2]<<16) +((uint32_t)k[3]<<24));
	b += (k[4] +((uint32_t)k[5]<<8) +((uint32_t)k[6]<<16) +((uint32_t)k[7]<<24));
	c += (k[8] +((uint32_t)k[9]<<8) +((uint32_t)k[10]<<16)+((uint32_t)k[11]<<24));
	mix(a,b,c);
	k += 12; len -= 12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c += length;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c+=((uint32_t)k[10]<<24);
		case 10: c+=((uint32_t)k[9]<<16);
		case 9 : c+=((uint32_t)k[8]<<8);
		  /* the first byte of c is reserved for the length */
		case 8 : b+=((uint32_t)k[7]<<24);
		case 7 : b+=((uint32_t)k[6]<<16);
		case 6 : b+=((uint32_t)k[5]<<8);
		case 5 : b+=k[4];
		case 4 : a+=((uint32_t)k[3]<<24);
		case 3 : a+=((uint32_t)k[2]<<16);
		case 2 : a+=((uint32_t)k[1]<<8);
		case 1 : a+=k[0];
		 /* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;

}

//------------------------------------

void CArchiveFS::LoadEntries() 
{
	// Get the file signature, verify it... use the result to decode the entries table

	// Verify the Archive Signature, and decode the Entry block
	CCryptoContext context;
	CKeyPair keyPair(&context);
	CHasher hasher(&context);
	CSigner signer;
	CTinyEncrypt tinyEnc;
	uint32_t i;

	// 1. Load the signature from the file
	uint32_t dwSignSize = 128;		//m_Header.headerV2.dwSignSize;
	uint8_t *pbSignature;
	uint32_t dwSignDataEnd;

	pbSignature = new uint8_t[dwSignSize];
	m_pStream->Seek((int)dwSignSize, CAbstractStream::SeekEnd);
                  //CrashLog("CArchiveFS::LoadEntries() | 1. Load the signature from the file");
	dwSignDataEnd = m_pStream->Tell();
	m_pStream->Read(pbSignature, dwSignSize);
	
	// 2. Hash the stuff (excluding the header and signature!)
	uint8_t *pbReadData;
	uint32_t dwReadSize;
	const uint32_t dwReadBlockSize = 10 * 1024;	// 10kb

	m_pStream->Seek(m_Header.SizeOf());			// start from the actual data section
	pbReadData = new uint8_t[dwReadBlockSize];
	for(i=m_Header.SizeOf(); i<dwSignDataEnd; ) {
		dwReadSize = m_pStream->Read(pbReadData, dwReadBlockSize);
		if (i+dwReadSize > dwSignDataEnd)
			hasher.AddData(dwSignDataEnd - i, pbReadData);
		else
			hasher.AddData(dwReadSize, pbReadData);
		i += dwReadSize;
	}
	delete[] pbReadData;

	// 3. Load the key and verify the signature
	bool bVerified;

                  keyPair.LoadFromMemory(RSA_PUB_KEY_SIZE, (uint8_t*)RSA_PUB_KEY, RSA_XOR_KEY);
	signer.SetSignature(dwSignSize, pbSignature);
	bVerified = signer.VerifySignature(&hasher, &keyPair);

	delete[] pbSignature;

	// Set the obfuscation decoding mask based on the bVerified value
	m_dwObfsMask = -((int)bVerified);		// if its 1 (true), then 0xffffffff, else 0.

	// 4. Decode the TEA encrypted archive entry

	m_pStream->Seek((dwSignDataEnd - m_dwNumEntries*sizeof(SAA_ENTRY)));
	uint32_t dwFilePos = m_pStream->Tell();
	m_pStream->Read(m_pEntries, sizeof(SAA_ENTRY), m_dwNumEntries);
	dwFilePos = m_pStream->Tell();

	tinyEnc.SetKey((uint8_t*)TEA_KEY, TEA_XOR_KEY);
	tinyEnc.DecryptData(sizeof(SAA_ENTRY)*m_dwNumEntries, reinterpret_cast<uint8_t*>(m_pEntries));

	// 5. Build a binary tree of the entries.. it makes searching for files faster (since we have a 
	//    huge index with fake entries)
	for(i=0; i<m_dwNumEntries; i++) {
		m_EntryBTreeRoot.AddEntry(&m_pEntries[i]);
	}

	// Done.

	m_bEntriesLoaded = true;

}

//------------------------------------

bool CArchiveFS::Load(char* szFileName) 
{
	if (m_bLoaded)
		Unload();

	m_pStream = new CFileStream(szFileName, CFileStream::TypeBinary, CFileStream::ModeRead);

	m_Header.Read(m_pStream);

	m_Header.XorV2Identifier();

	m_bLoaded = true;

	if (!m_Header.VerifyIdentifier()) {
		Unload();
		return false;
	}

	return true;
}

//------------------------------------

bool CArchiveFS::Load(uint8_t* pbData, uint32_t nLength)
{
	if (m_bLoaded)
		Unload();

	m_pStream = new CMemoryStream(pbData, nLength);

	m_Header.Read(m_pStream);

	m_Header.XorV2Identifier();

	m_bLoaded = true;

	if (!m_Header.VerifyIdentifier()) {
		Unload();
		return false;
	}

	return true;
}

//------------------------------------

void CArchiveFS::Unload() 
{
	if (!m_bLoaded)
		return;

	delete m_pStream;
	m_pStream = nullptr;

	m_bLoaded = false;
	m_bEntriesLoaded = false;
}

//------------------------------------

uint32_t CArchiveFS::GetFileIndex(uint32_t dwFileHash)
{

	if (!m_bEntriesLoaded)
		LoadEntries();

	AFS_ENTRYBT_NODE* node = m_EntryBTreeRoot.FindEntry(dwFileHash);
	
	if (node == nullptr) {
		return FS_INVALID_FILE;
	}

	SAA_ENTRY saaEntry = *(node->pEntry);	// Always make a copy of saaEntry before decrypting it
											// Otherwise, the data decryption will get messed up
	
	saaEntry.dwDataBlock = UNOBFUSCATE_DATA(saaEntry.dwDataBlock) ^ (saaEntry.dwFileNameHash & this->m_dwObfsMask);
	if (node->pEntry == &(m_pEntries[saaEntry.dwPrevEntry]))
		return FS_INVALID_FILE;

	// Okay, we got a file. 
	// TODO: It might be wise at this point to start a thread to decrypt the data
	// Chances are if the index was requested, data for it will be requested.

	// Painfully evil conversion from SAA_ENTRY* to DWORD
	uint32_t* ppEntry = reinterpret_cast<uint32_t*>(&node);
	return *ppEntry;

}

//------------------------------------

uint32_t CArchiveFS::GetFileIndex(char* szFileName) 
{
	// PRE: szFileName must be the filename only (no paths!)

	if (!m_bEntriesLoaded)
		LoadEntries();

	char szFileNameLC[MAX_PLAYERS];
	strcpy(szFileNameLC, szFileName);
	strlen(szFileNameLC);

	uint32_t dwHash = this->HashString(szFileNameLC);

	uint32_t dwIndex = GetFileIndex(dwHash);

	/*if (dwIndex != FS_INVALID_FILE)
	{
		CHAR szDebugMsg[1024];
		sprintf(szDebugMsg, "ArchiveFS: Requested file: %s...\n", szFileNameLC);
		OutputDebugString(szDebugMsg);
	}*/

	return dwIndex;


}

//------------------------------------

uint32_t CArchiveFS::GetFileSize(uint32_t dwFileIndex) 
{
	AFS_ENTRYBT_NODE* node = *(reinterpret_cast<AFS_ENTRYBT_NODE**>(&dwFileIndex));
	
	SAA_ENTRY saaEntry = *(node->pEntry);	// Make a copy!
	saaEntry.dwDataBlock = UNOBFUSCATE_DATA(saaEntry.dwDataBlock) ^ (saaEntry.dwFileNameHash & this->m_dwObfsMask);
	return saaEntry.dwFileSize;
}

//------------------------------------

uint8_t* CArchiveFS::GetFileData(uint32_t dwFileIndex) 
{
	CTinyEncrypt tinyEnc;

	AFS_ENTRYBT_NODE* node = *(reinterpret_cast<AFS_ENTRYBT_NODE**>(&dwFileIndex));
	
	SAA_ENTRY saaEntry = *(node->pEntry);	// Make a copy!
	saaEntry.dwDataBlock = UNOBFUSCATE_DATA(saaEntry.dwDataBlock) ^ (saaEntry.dwFileNameHash & this->m_dwObfsMask);

	uint32_t dwFileSize;

	if (node->pbData != nullptr) {
		return node->pbData;
	} else {
		// Alloc memory (in blocks!)
		dwFileSize = saaEntry.dwFileSize;
		if (dwFileSize % SAA_BLOCK_SIZE != 0)
			dwFileSize += (SAA_BLOCK_SIZE - (dwFileSize % SAA_BLOCK_SIZE));
		
		node->pbData = new uint8_t[dwFileSize];

		// Determine offset to data
		SAA_ENTRY prevEntry;
		uint32_t dwDataOffset = m_Header.SizeOf();

		if (saaEntry.dwPrevEntry != m_Header.headerV2.dwInvalidIndex) {
			prevEntry = saaEntry;
			do {
				prevEntry = m_pEntries[prevEntry.dwPrevEntry];
				prevEntry.dwDataBlock = UNOBFUSCATE_DATA(prevEntry.dwDataBlock) ^ (prevEntry.dwFileNameHash & this->m_dwObfsMask);

				dwFileSize = prevEntry.dwFileSize;
				if (dwFileSize % SAA_BLOCK_SIZE != 0)
					dwFileSize += (SAA_BLOCK_SIZE - (dwFileSize % SAA_BLOCK_SIZE));
				dwDataOffset += dwFileSize;
				
			} while(prevEntry.dwPrevEntry != m_Header.headerV2.dwInvalidIndex);
		}

		m_pStream->Seek(dwDataOffset);

		// Load the data in blocks and decrypt it
		uint8_t* pbTEAKey = reinterpret_cast<uint8_t*>(this->m_pEntries) + 
								(saaEntry.dwFileNameHash % (sizeof(SAA_ENTRY)*m_dwNumEntries-TEA_KEY_SIZE));

		tinyEnc.SetKey(pbTEAKey, 0);

		for(uint32_t i=0; i<saaEntry.dwFileSize; i+=SAA_BLOCK_SIZE) {
			m_pStream->Read(node->pbData+i, SAA_BLOCK_SIZE);
			tinyEnc.DecryptData(SAA_BLOCK_SIZE, node->pbData+i);
		}

		return node->pbData;
	}
}

void CArchiveFS::UnloadData(uint32_t dwFileIndex) 
{
	AFS_ENTRYBT_NODE* node = *(reinterpret_cast<AFS_ENTRYBT_NODE**>(&dwFileIndex));
	
	if (node->pbData != nullptr) 
	{
		delete[] node->pbData;
		node->pbData = nullptr;
	}
}