#pragma once

#include "ArchiveCommon.h"
#include "Obfuscator.h"
#include "Stream.h"

#include "mod.h"

#ifndef ARCTOOL

// Load the original CFileSystem class
#include "../FileSystem.h"

#endif

#define FS_INVALID_FILE	0xFFFFFFFF

typedef struct _AFS_ENTRYBT_NODE 
{
	SAA_ENTRY* pEntry;
	_AFS_ENTRYBT_NODE* pLNode;
	_AFS_ENTRYBT_NODE* pRNode;
	uint8_t* pbData;

	_AFS_ENTRYBT_NODE()
	{
		this->pEntry = nullptr;
		this->pLNode = nullptr;
		this->pRNode = nullptr;
		this->pbData = nullptr;
	}

	_AFS_ENTRYBT_NODE(SAA_ENTRY* pSAAEntry)
	{
		this->pEntry = pSAAEntry;
		this->pLNode = nullptr;
		this->pRNode = nullptr;
		this->pbData = nullptr;
	}

	void AddEntry(SAA_ENTRY* pSAAEntry) 
	{
		if (this->pEntry == nullptr) {
			this->pEntry = pSAAEntry;
		} else {
			if (pSAAEntry->dwFileNameHash < this->pEntry->dwFileNameHash) {
				if (this->pLNode == nullptr)
					this->pLNode = new _AFS_ENTRYBT_NODE(pSAAEntry);
				else
					this->pLNode->AddEntry(pSAAEntry);
			} else {
				if (this->pRNode == nullptr)
					this->pRNode = new _AFS_ENTRYBT_NODE(pSAAEntry);
				else
					this->pRNode->AddEntry(pSAAEntry);
			}
		}
	}

	_AFS_ENTRYBT_NODE* FindEntry(uint32_t dwHash) 
	{
		if (this->pEntry->dwFileNameHash == dwHash) {
			return this;
		} else {
			if (dwHash < this->pEntry->dwFileNameHash) {
				if (this->pLNode == nullptr)
					return nullptr;
				else
					return this->pLNode->FindEntry(dwHash);
			} else {
				if (this->pRNode == nullptr)
					return nullptr;
				else
					return this->pRNode->FindEntry(dwHash);
			}	
		}
	}

	~_AFS_ENTRYBT_NODE() 
	{
		if (this->pLNode != nullptr)
			delete this->pLNode;
		if (this->pRNode != nullptr)
			delete this->pRNode;
		if (this->pbData != nullptr)
			delete[] this->pbData;
	}

} AFS_ENTRYBT_NODE;

const uint32_t FILES_FORCE_FS[] = 
{
	OBFUSCATE_DATA( 0x5440792e ), //ar_stats.dat
	OBFUSCATE_DATA( 0x57d2bfe5 ), //carmods.dat
	OBFUSCATE_DATA( 0x4e643d5e ), //default.dat
	OBFUSCATE_DATA( 0x2acf3319 ), //default.ide
	OBFUSCATE_DATA( 0xe9a7df22 ), //gta.dat
	OBFUSCATE_DATA( 0x2cc7ce25 ), //handling.cfg
	OBFUSCATE_DATA( 0xd83f24dd ), //main.scm
	OBFUSCATE_DATA( 0xcbc78e39 ), //melee.dat
	OBFUSCATE_DATA( 0xb7ffa1cb ), //object.dat
	OBFUSCATE_DATA( 0x6fdca2be ), //ped.dat
	OBFUSCATE_DATA( 0x6c62978a ), //peds.ide
	OBFUSCATE_DATA( 0x11a462d1 ), //script.img
	OBFUSCATE_DATA( 0x131fad35 ), //shopping.dat
	OBFUSCATE_DATA( 0x4633bceb ), //stream.ini
	OBFUSCATE_DATA( 0xc1d9e789 ), //timecyc.dat
	OBFUSCATE_DATA( 0xee6dfcb7 ), //vehicles.ide
	OBFUSCATE_DATA( 0xebfa9ab6 ), //weapon.dat
	OBFUSCATE_DATA( 0x7a504fb9 ), //loadscv.txd  (remote process AC dll)
	OBFUSCATE_DATA( 0xa848b69a ), //bindat.bin
};

class CArchiveFS 
#ifndef ARCTOOL
	: public CFileSystem
#endif
{
private:
	bool m_bLoaded;
	CAbstractStream *m_pStream;
	bool m_bEntriesLoaded;
	SAA_FILE_HEADER m_Header;
	SAA_ENTRY m_pEntries[SAA_MAX_ENTRIES];
	AFS_ENTRYBT_NODE m_EntryBTreeRoot;
	uint32_t m_dwObfsMask;
	uint32_t m_dwNumEntries;

	void LoadEntries();

	static uint32_t ms_dwHashInit;
	uint32_t HashString(char* szString);

public:
	CArchiveFS(void);
	CArchiveFS(uint32_t dwNumEntries, uint32_t dwFDSize);
	~CArchiveFS(void);

	bool Load(char* szFileName);
	bool Load(uint8_t* pbData, uint32_t nLength);
	void Unload();

	uint32_t GetFileIndex(uint32_t dwFileHash);
	uint32_t GetFileIndex(char* szFileName);
	uint32_t GetFileSize(uint32_t dwFileIndex);
	uint8_t* GetFileData(uint32_t dwFileIndex);

	void UnloadData(uint32_t dwFileIndex);
};
