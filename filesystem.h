#pragma once

//----------------------------------------------------------

#define FS_FILE_MAGIC	0x32414153	// "SAA2"
#define FS_BLOCK_SIZE	0x800		// 2kb
#define FS_INVALID_FILE	0xFFFFFFFF
#define FS_ENCKEY_VAR	37625
#define FS_ENC_CONST1	54825
#define FS_ENC_CONST2	91722

//----------------------------------------------------------

typedef struct _FS_HEADER
{
	uint32_t dwSAAV;
	uint32_t dwFileCount;
	uint16_t  wKey;
} FS_HEADER;

typedef struct _FS_FILE_ENTRY
{
	uint32_t dwOffset;
	uint32_t dwSize;
	char szName[24];
	uint32_t dwRealSize;
	uint16_t wKey;
} FS_FILE_ENTRY;

//----------------------------------------------------------

class CFileSystem
{
private:
	bool m_bLoaded;
	uint32_t m_dwFileCount;
	uint16_t m_wKey;
	FS_FILE_ENTRY* m_pFileList;
	uint8_t** m_pFileData;
public:
	CFileSystem();
	~CFileSystem();

	void Load(char* szFileName, ...);
	void Unload();

	uint32_t GetFileIndex(char* szFileName);
	uint32_t GetFileSize(uint32_t dwFileIndex);
	uint8_t* GetFileData(uint32_t dwFileIndex);

	void DecryptData(uint8_t* pData, uint32_t dwDataLen, uint16_t wKey);
};