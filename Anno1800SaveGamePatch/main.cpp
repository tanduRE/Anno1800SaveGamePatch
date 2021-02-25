#include "SigScanner.h"


int main()
{
	SignatureScanner SigScanner = {};

	if (SigScanner.GetProcess("Anno1800.exe"))
	{
		auto mod = SigScanner.GetModule("Anno1800.exe");

		auto isMultiPlayerPatch = SigScanner.FindSignature(mod.dwBase, mod.dwSize, "\xE8\x00\x00\x00\x00\x4D\x8D\x86\x00\x00\x00\x00\x4C\x89\xF1", "x????xxx????xxx");
		if(!isMultiPlayerPatch)
		{
			printf("sig not found!\n");
			getchar();
			return 0;
		}

		printf("Sig %p\n", isMultiPlayerPatch);
		

		BYTE backup[5] = { 0 };
		
		ReadProcessMemory(SigScanner.TargetProcess, (LPCVOID)isMultiPlayerPatch, backup, sizeof(backup), nullptr);

		BYTE nops[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
		WriteProcessMemory(SigScanner.TargetProcess, (LPVOID)isMultiPlayerPatch, nops, sizeof(nops), nullptr);

		printf("Press key to restore patch\n");
		getchar();

		WriteProcessMemory(SigScanner.TargetProcess, (LPVOID)isMultiPlayerPatch, backup, sizeof(backup), nullptr);

		printf("done\n");
	}


	getchar();
}
