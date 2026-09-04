#pragma once

#include <string>
#include <vector>

struct PatternPair
{
	std::string pattern;
	int offset;
};

void initializeGame();
static void LegacyPatch();
static void EnhancedPatch();
void RelocateAbsoluePackFileArray(void* newPackFileArray, const std::vector<PatternPair>& list);
void RelocateRelativePackFileArray(void* newPackFileArray, const std::vector<PatternPair>& list);
void AdjustPackFileArrayLimit();
LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity);
void* AllocateStubMemory(size_t size);
static void SetStreamingInterface(char* si);
void FatalErrorExit();