#include "EmberEyes.h"
#include "Brc4.h"

int main(int argc, char** argv)
{
	char symbol = NULL;
	char* argv1 = nullptr;
	EmberEyes ees;
	Brc4 brc4;
	if (argc < 2) 
	{
		ees.PrintBannerHelpMenu();
		system("pause");
		return 0;
	}
	argv1 = argv[1];
	symbol = *argv1;
	if (symbol == '/' || symbol == '-') 
	{
		if (!_stricmp(argv1 + 1, "?") || !_stricmp(argv1 + 1, "h") || !_stricmp(argv1 + 1, "help")) 
		{
			ees.PrintBannerHelpMenu();
		}
		else if (!_stricmp(argv1 + 1, "s") || !_stricmp(argv1 + 1, "search")) 
		{
			brc4.ScanAllProcessMem();
		}
		else if (argc == 3 && !_stricmp(argv1 + 1, "e") || !_stricmp(argv1 + 1, "extract")) 
		{
			brc4.Brc4ConfigExtract(argv[2]);
		}
		else if (argc == 3 && !_stricmp(argv1 + 1, "p") || !_stricmp(argv1 + 1, "print"))
		{
			brc4.PrintBrc4Config(argv[2]);
		}
		else if (argc == 4 && !_stricmp(argv1 + 1, "f") || !_stricmp(argv1 + 1, "fake")) 
		{
			brc4.FakeOnlineBrc4Badger(argv[2], atoi(argv[3]));
		}
		else if (argc == 4 && !_stricmp(argv1 + 1, "d") || !_stricmp(argv1 + 1, "decrypt")) 
		{
			brc4.DecryptBase64Brc4Encrypt(argv[2], argv[3]);
		}
	}
	return 0;
}