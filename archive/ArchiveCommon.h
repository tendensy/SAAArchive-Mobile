#pragma once

#include "Stream.h"

// SAA_FILE_ID := {'S', 'A', 'M', 'P'} ignoring first 3 bits of each char
//	first 3 bits are 010 anyhow :)
#define SAA_FILE_ID		0x83433
#define SAA_FILE_VERSION	                  2
#define SAA_BLOCK_SIZE		2048
#define SAA_MAX_ENTRIES		256
#define SAA_MAX_FAKEDATA	120

typedef struct _SAA_ENTRY
{
	uint32_t dwFileNameHash;
	union 
	{
		struct 
		{
			uint32_t dwPrevEntry	: 8;		// index to previous entry (link to fake entry if none)
			uint32_t dwFileSize	: 24;		// 24bits = max filesize of 16mb
		};
		uint32_t dwDataBlock;
	};
} SAA_ENTRY;


typedef struct _SAA_FILE_HEADER
{
	// This is a fake header
	struct VER1_HEADER 
	{
		uint32_t dwSAAV;
		uint32_t dwFileCount;
		uint16_t wFakeData[SAA_MAX_FAKEDATA];
	} headerV1; /* 248 bytes */
	
	struct VER2_HEADER 
	{
		union 
		{
			struct 
			{
				uint32_t dwSAMPID		: 20;
				uint32_t dwVersion		: 3;
				uint32_t dwSignSize	: 8;
				uint32_t dwPadding1	: 1;
			};
			uint32_t dwCompleteID;
		};
		union
		{
			struct 
			{
				uint32_t dwPadding2	: 5;
				uint32_t dwInvalidIndex	: 8;
				uint32_t dwPadding3	: 19;
			};
			uint32_t dwXORKey;
		};
	} headerV2;	/* 8 bytes */

	uint32_t dwFakeDataSize;

	_SAA_FILE_HEADER()
	{
		dwFakeDataSize = SAA_MAX_FAKEDATA;
	}

	uint32_t SizeOf()
	{
		return(sizeof(uint32_t)*2 + sizeof(uint16_t)*dwFakeDataSize + sizeof(VER2_HEADER));
	}

#ifdef ARCTOOL
	void InitializeDataV1()
	{
		headerV1.dwSAAV = 0x32414153;	// "SAA2"
		headerV1.dwFileCount = 0x16;
		// All other data should be random, or predefined outside.
	}

	void InitializeDataV2()
	{
		headerV2.dwSAMPID = SAA_FILE_ID;
		headerV2.dwVersion = SAA_FILE_VERSION;
	}

	void Write(FILE *f)
	{
		fseek(f, 0, SEEK_SET);
		fwrite(&headerV1, 1, sizeof(uint32_t)*2 + sizeof(uint16_t)*dwFakeDataSize, f);
		fwrite(&headerV2, 1, sizeof(VER2_HEADER), f);
	}

#endif

	bool VerifyIdentifier()
	{
		return ((headerV2.dwSAMPID == SAA_FILE_ID) && 
				(headerV2.dwVersion == SAA_FILE_VERSION));
	}

	void XorV2Identifier() {
		this->headerV2.dwCompleteID ^= this->headerV2.dwXORKey;
	}

	void Read(FILE *f)
	{
		fread(&headerV1, 1, sizeof(uint32_t)*2 + sizeof(uint16_t)*dwFakeDataSize, f);
		fread(&headerV2, 1, sizeof(VER2_HEADER), f);
	}

	void Read(CAbstractStream *pStream)
	{
		pStream->Read(&headerV1, sizeof(uint32_t)*2 + sizeof(uint16_t)*dwFakeDataSize);
		pStream->Read(&headerV2, sizeof(VER2_HEADER));
	}

} SAA_FILE_HEADER;
