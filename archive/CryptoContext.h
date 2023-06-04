#pragma once

class CCryptoContext
{
private:
	static char* ms_szProviderName;
	static char* ms_szContainerName;

public:
	CCryptoContext(void);
	~CCryptoContext(void);

#ifdef ARCTOOL
	void GenerateRandom(uint32_t dwLength, uint8_t* pbBuffer);
#endif

};
