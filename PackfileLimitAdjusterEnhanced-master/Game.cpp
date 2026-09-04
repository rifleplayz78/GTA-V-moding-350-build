#include "pch.h"
#include <cstdint>
#include <string_view>
#include <cassert>
#include "Game.h"
#include <fstream>
#include "Hooking.h"
#include "Logging.h"
#include "GameVersion.h"

bool g_isEnhanced;
uint32_t VanillaPackFileArray_Size;
uint32_t VanillaPackFileArray_InConfigFile_Size;
uint32_t PackFileArray_Size;
void** newArray;

constexpr FileVersion VERSION_1_1013_17_E{ 1, 0, 1013, 17 }; // Mansions DLC
constexpr FileVersion VERSION_1_1158_13_E{ 1, 0, 1158, 13 }; // Kortz Center DLC

static void(*g_origSetStreamingInterface)(char*);

static void SetStreamingInterface(char* si)
{
	VanillaPackFileArray_InConfigFile_Size = *(uint32_t*)(si + 24);
	*(uint32_t*)(si + 24) = PackFileArray_Size; // Same in Enhanced

	std::string msg = "Vanilla Packfile List Size is: " + std::to_string(VanillaPackFileArray_Size) + "\n"
	+ "Vanilla Packfile List Size From ConfigFile is: " + std::to_string(VanillaPackFileArray_InConfigFile_Size) + "\n"
	+ "Packfile List Size Adjusted to: " + std::to_string(PackFileArray_Size);

	Logging(msg); // Log everything here, as VanillaPackFileArray_InConfigFile_Size is only initialized when the hook is called

	g_origSetStreamingInterface(si);
}

void initializeGame() 
{
	ClearLog();

	PackFileArray_Size = (uint32_t)GetPrivateProfileIntA("PACKFILE_SETTINGS", "PACKFILEARRAY_SIZE", 12000, ".\\PackfileLimitAdjusterEnhanced.ini");
	g_isEnhanced = [] {
		char path[MAX_PATH];
		GetModuleFileNameA(GetModuleHandleA(nullptr), path, MAX_PATH);

		const char* filename = strrchr(path, '\\');
		filename = filename ? filename + 1 : path;

		return (_stricmp(filename, "GTA5_Enhanced.exe") == 0);
	}();

	newArray = (void**)AllocateStubMemory(sizeof(void*) * PackFileArray_Size);

	memset(newArray, 0, sizeof(void*) * PackFileArray_Size);

	if (g_isEnhanced) 
	{
		EnhancedPatch();
	}
	else 
	{
		LegacyPatch();
	}

	AdjustPackFileArrayLimit();
}

static void LegacyPatch() {

	DWORD oldProtect;

	// Direct size
	auto address = MemScanner::FindPatternBmh("66 41 03 d2 b8 ? ? ? ? 66 3b d0");
	address += 5;
	VirtualProtect(address, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect);
	VanillaPackFileArray_Size = *(uint32_t*)address;
	*(uint32_t*)address = PackFileArray_Size;
	VirtualProtect(address, sizeof(uint32_t), oldProtect, &oldProtect);
	
	// Indirect size
	address = MemScanner::FindPatternBmh("3b 05 ? ? ? ? 7d ? 4c 8d 05");
	address += 2;
	uint8_t* indirectAddr = reinterpret_cast<uint8_t*>(address) + *(int32_t*)address + 4;
	VirtualProtect(indirectAddr, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect);
	*reinterpret_cast<uint32_t*>(indirectAddr) = PackFileArray_Size;
	VirtualProtect(indirectAddr, sizeof(uint32_t), oldProtect, &oldProtect);
		
	RelocateAbsoluePackFileArray(newArray,{
		{ "4d 8b ac c7 ? ? ? ? 4c 8d 45", 4 },
		{ "4c 8b bc c1 ? ? ? ? 4d 85 ff 0f 84", 4 }
	});

	address = MemScanner::FindPatternBmh("74 1b 8b 8b ? ? ? ? 48 89 78 ? 48 89 70 ? 89 48");
	address += 0x20;
	auto h = HookManager::SetCall((char*)address, SetStreamingInterface);
	g_origSetStreamingInterface = h->fn;
}

static void EnhancedPatch() {

	DWORD oldProtect;
	// Direct size

	uint8_t* address;
	if (GetCurrentProcessVersionComparable() >= VERSION_1_1158_13_E.ToComparable()) {
		address = MemScanner::FindPatternBmh("48 83 C6 ? 48 81 F9");
		address += 7;
	}
	else if (GetCurrentProcessVersionComparable() >= VERSION_1_1013_17_E.ToComparable()) {
		address = MemScanner::FindPatternBmh("49 83 c3 ? 48 81 f9 ? ? ? ? 75 ? eb");
		address += 7;
	}
	else {
		address = MemScanner::FindPatternBmh("48 81 f9 ? ? ? ? 74 ? 48 83 3c ca 00");
		address += 3;
	}
	
	VirtualProtect(address, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect);
	VanillaPackFileArray_Size = *(uint32_t*)address;
	*(uint32_t*)address = PackFileArray_Size;
	VirtualProtect(address, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect);

	// Indirect size
	address = MemScanner::FindPatternBmh("3b 05 ? ? ? ? 0f 8d ? ? ? ? 89 c0");
	address += 2;
	uint8_t* indirectAddr = reinterpret_cast<uint8_t*>(address) + *(int32_t*)address + 4;
	VirtualProtect(indirectAddr, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect);
	*reinterpret_cast<uint32_t*>(indirectAddr) = PackFileArray_Size;
	VirtualProtect(indirectAddr, sizeof(uint32_t), oldProtect, &oldProtect);

	address = MemScanner::FindPatternBmh("89 48 ? 48 8d 0d ? ? ? ? 48 89 08 48 89 c1 e8");
	address += 0x10;
	auto h = HookManager::SetCall((char*)address, SetStreamingInterface);
	g_origSetStreamingInterface = h->fn;
	
}

void RelocateAbsoluePackFileArray(void* newPackFileArray, const std::vector<PatternPair>& list) {
	
	int32_t oldAddress = 0;

	uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
	int32_t newArrayRVA = static_cast<int32_t>(reinterpret_cast<uintptr_t>(newPackFileArray) - moduleBase);

	for (auto& entry : list)
	{
		auto address = MemScanner::FindPatternBmh(entry.pattern);
		address += entry.offset;
		if (!oldAddress)
		{
			oldAddress = *(uint32_t*)address;
		}

		auto curTarget = *(uint32_t*)address;
		assert(curTarget == oldAddress);

		DWORD oldProtect;
		VirtualProtect(address, sizeof(int32_t), PAGE_EXECUTE_READWRITE, &oldProtect);
		*(int32_t*)address = newArrayRVA;
		VirtualProtect(address, sizeof(int32_t), oldProtect, &oldProtect);
	}

}

void RelocateRelativePackFileArray(void* newPackFileArray, const std::vector<PatternPair>& list)
{
	void* oldAddress = nullptr;

	for (auto& entry : list)
	{
		auto address = MemScanner::FindPatternBmh(entry.pattern);
		address += entry.offset;
		if (!oldAddress)
		{
			oldAddress = *(int32_t*)address + address + 4;
		}

		auto curTarget = *(int32_t*)address + address + 4;;
		assert(curTarget == oldAddress);

		DWORD oldProtect;
		VirtualProtect(address, sizeof(int32_t), PAGE_EXECUTE_READWRITE, &oldProtect);
		*(int32_t*)address = static_cast<int32_t>((intptr_t)newPackFileArray - (intptr_t)address - 4);
		VirtualProtect(address, sizeof(int32_t), oldProtect, &oldProtect);
	}
}

void AdjustPackFileArrayLimit()
{
	std::vector<PatternPair> patternPairs;
	
	if (g_isEnhanced) {
		patternPairs = {
			// Data
			{ "48 8d 15 ? ? ? ? 48 8b 3c ca 48 8b 2f", 3 },
			{ "48 8d 3d ? ? ? ? 48 8b 0c cf 48 85 c9", 3 },
			{ "48 8d 3d ? ? ? ? 48 8b 0c 39 48 85 c9", 3 },
			{ "89 c0 48 8d 0d ? ? ? ? 48 8b 0c c1 48 85 c9 74", 5 },
			{ "89 c0 48 8d 0d ? ? ? ? 48 8b 0c c1 48 85 c9 0f 84", 5 },
			{ "48 8d 0d ? ? ? ? 4a 8b 0c c9 48 85 c9 0f 84 ? ? ? ? 48 8b 01", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 1c 08 48 8b 03", 3 },
			{ "48 8d 0d ? ? ? ? 4a 8b 0c c1 48 85 c9", 3 },
			{ "48 83 ec ? 48 89 ce 48 8d 05 ? ? ? ? 48 89 01 c6 81", 39 },
			{ "48 c1 e8 ? 48 8d 0d ? ? ? ? 48 8b 0c c1 48 8b 01", 7 },
			{ "48 8d 0d ? ? ? ? 48 83 3c c1 ? 40 0f 95 c6 eb", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 0c 08 48 8b 01 ff 90 ? ? ? ? 48 8b 48", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 0c 08 48 8b 01 4c 8d 44 24", 3 },
			{ "48 8d 0d ? ? ? ? 4c 8b 24 08 49 8b 04 24 4c 8d 44 24", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 0c 08 48 85 c9 75", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 0c c1 48 85 c9 0f 84 ? ? ? ? 48 89 f5", 3 },
			{ "48 83 ec ? 89 d7 48 89 ce 48 8d 05 ? ? ? ? 48 89 01 c6 81 c1", 41 },
			{ "48 8d 0d ? ? ? ? 48 8b 3c 08 48 8b 07 48 89 f9", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 0c 08 48 8b 01 ff 90 ? ? ? ? 48 8b 40", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 0c d1 48 85 c9 75", 3 },
			{ "48 8d 0d ? ? ? ? 4c 8b 24 c1 4d 85 e4 0f 84", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 0c c1 48 8b 01 ff 90 ? ? ? ? 48 8b 38", 3 },
			// Write
			{ "48 89 2d ? ? ? ? b9 ? ? ? ? ba ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? 48 c7 44 08", 3},
			{ "48 89 35 ? ? ? ? b9 ? ? ? ? ba ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? 0f 1f 44 00 00", 3},
			{ "48 89 3d ? ? ? ? b9 ? ? ? ? ba ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? 66 90", 3}, 
			{ "48 89 35 ? ? ? ? b9 ? ? ? ? ba ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? 66 66 66 2e 0f 1f 84 00 00 00 00 00", 3},
			{ "48 89 2d ? ? ? ? b9 ? ? ? ? ba ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? 0f 1f 84 00 00 00 00 00", 3},
			{ "48 89 3d ? ? ? ? b9 ? ? ? ? ba ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? 66 66 66 66 2e 0f 1f 84 00 00 00 00 00", 3},
			{ "48 89 3d ? ? ? ? b9 ? ? ? ? ba ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? 0f 1f 40 00", 3},
			{ "48 89 35 ? ? ? ? b9 ? ? ? ? ba ? ? ? ? e8 ? ? ? ? b9 ? ? ? ? 48 c7 44 08", 3},
		};

		patternPairs.emplace_back(GetCurrentProcessVersionComparable() >= VERSION_1_1158_13_E.ToComparable() ?
			PatternPair{ "BF ? ? ? ? BE ? ? ? ? 4C 8D 05", 13 } : PatternPair{ "41 ? ? ? ? ? ? ? ? ? ? 41 bb ? ? ? ? ? 8d", 20 });
	}
	else {
		patternPairs = {
			// Data
			{ "ff 90 ? ? ? ? 48 8b c8 48 8b 00 48 c1 e8", -22 },
			{ "ff 90 ? ? ? ? 48 8b 08 48 c1 e9 ? f6 c1", -22 },
			{ "4c 8d 25 ? ? ? ? 89 58 ? 45 85 f6 0f 84", 3 },
			{ "48 8d 35 ? ? ? ? 8b d0 c1 e9", 3 },
			{ "4c 8d 0d ? ? ? ? 48 89 01 4c 89 81", 3 },
			{ "48 8d 0d ? ? ? ? 48 89 3c c1", 3 },
			{ "48 8d 0d ? ? ? ? 48 39 1c f9", 3 },
			{ "48 8d 0d ? ? ? ? 48 8b 0c c1 4c 8d 44 24", 3 },
			{ "48 8d 05 ? ? ? ? c1 e9 ? 48 8b 0c c8 48 8b 01", 3 },
			{ "4c 8d 0d ? ? ? ? 4d 8b 0c c1 4d 85 c9", 3 },
			{ "48 8d 3d ? ? ? ? 83 f9 ? 74 ? 8b c1", 3 },
			{ "4c 8d 05 ? ? ? ? 4d 8b 04 c0 4d 85 c0 74 ? 49 8b", 3 },
			{ "48 8d 0d ? ? ? ? 8b d0 c1 ea ? 48 8b 0c d1", 3 },
			{ "48 8d 1d ? ? ? ? c1 e8 ? 48 8b 1c c3", 3 },
			{ "48 8d 05 ? ? ? ? c1 e9 ? 48 8b 0c c8 48 85 c9", 3 },
			{ "8b 11 48 8d 0d ? ? ? ? 48 8b 0c c1", 5 },
			// Write
			{ "48 89 3d ? ? ? ? e8 ? ? ? ? 48 8d 47", 3 },
		};
	}

	RelocateRelativePackFileArray(newArray, patternPairs);
}

LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity)
{
	ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

	// Round down to the next allocation granularity.
	tryAddr -= tryAddr % dwAllocationGranularity;

	// Start from the previous allocation granularity multiply.
	tryAddr -= dwAllocationGranularity;

	while (tryAddr >= (ULONG_PTR)pMinAddr)
	{
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) ==
			0)
			break;

		if (mbi.State == MEM_FREE)
			return (LPVOID)tryAddr;

		if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity)
			break;

		tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
	}

	return NULL;
}

void* AllocateStubMemory(size_t size)
{
	// Max range for seeking a memory block. (= 1024MB)
	const uint64_t MAX_MEMORY_RANGE = 0x40000000;

	void* origin = GetModuleHandle(NULL);

	ULONG_PTR minAddr;
	ULONG_PTR maxAddr;

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
	maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

	if ((ULONG_PTR)origin > MAX_MEMORY_RANGE &&
		minAddr < (ULONG_PTR)origin - MAX_MEMORY_RANGE)
		minAddr = (ULONG_PTR)origin - MAX_MEMORY_RANGE;

	if (maxAddr > (ULONG_PTR)origin + MAX_MEMORY_RANGE)
		maxAddr = (ULONG_PTR)origin + MAX_MEMORY_RANGE;

	LPVOID pAlloc = origin;

	void* stub = nullptr;
	while ((ULONG_PTR)pAlloc >= minAddr)
	{
		pAlloc = FindPrevFreeRegion(pAlloc, (LPVOID)minAddr, si.dwAllocationGranularity);
		if (pAlloc == NULL)
			break;

		stub = VirtualAlloc(pAlloc, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (stub != NULL)
			break;
	}

	return stub;
}

void FatalErrorExit() {
	Logging("FATAL ERROR, EXITING...");

	MessageBoxA(
		nullptr,
		"FATAL ERROR.\nCheck the Log for details.",
		"PackFileLimitAdjuster Enhanced",
		MB_OK | MB_ICONERROR
	);

	exit(1);
}