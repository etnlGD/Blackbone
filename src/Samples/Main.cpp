#include <BlackBone/Process/Process.h>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Process/RPC/RemoteFunction.hpp>
#include <BlackBone/Syscalls/Syscall.h>
#include <iostream>

using namespace blackbone;

void MapCalcFromFile();
void MapCmdFromMem();

class DiffPatternSearchPolicy : public PatternSearchPolicy
{
public:
	virtual void Process(ptr_t remoteAddress, uint8_t* scanStart, size_t scanSize, std::vector<ptr_t>& out)
	{
		if (sizeOfPtr == 4 && remoteAddress >= 0xffffffff)
			return;

		size_t step = align ? sizeOfPtr : 1;
		if (sizeOfPtr == 4)
		{
			for (size_t i = 0; i < scanSize - sizeOfPtr; i += step, remoteAddress += step)
			{
				int32_t valueAtAddress = *((int32_t*)&scanStart[i]);
				if (valueAtAddress - (int32_t)remoteAddress == diff1)
				{
					if (i + diff3 < scanSize - sizeOfPtr)
					{
						valueAtAddress = *((int32_t*)&scanStart[i + diff3]);
						if (valueAtAddress - (int32_t)(remoteAddress + diff3) == diff2)
						{
							out.push_back((ptr_t)(scanStart + i) - offset);
						}
					}
				}
			}
				
		}
// 		else if (sizeOfPtr == 8)
// 		{
// 			for (size_t i = 0; i < scanSize - sizeOfPtr; i += step, remoteAddress += step)
// 			{
// 				int64_t valueAtAddress = *((int64_t*)&scanStart[i]);
// 				if (valueAtAddress - (int64_t)remoteAddress == diff)
// 					out.push_back((ptr_t)(scanStart + i));
// 			}
// 		}
	}

	size_t sizeOfPtr = 4;
	int64_t diff1 = 0;
	int64_t diff2 = 0;
	int64_t diff3 = 0;
	int64_t offset = 0;
	bool align = true;
};

class LuaJIT_v1_1_5_StringSearchPolicy : public PatternSearchPolicy
{
public:
	void setTargetString(const char* str)
	{
		targetString = str;
		m_Len = (uint32_t)targetString.size();
	}

	virtual void Process(ptr_t remoteAddress, uint8_t* scanStart, size_t scanSize, std::vector<ptr_t>& out)
	{
		const uint8_t* cstart = (const uint8_t*)scanStart;
		const uint8_t* cend = cstart + scanSize;
		for (;;)
		{
			const uint8_t* res = std::search(cstart, cend, targetString.begin(), targetString.end());
			if (res >= cend)
				break;

			if (res - scanStart >= 16 && res + m_Len < cend) // sizeof(TString) == 16
			{
				if (((uint32_t*)res)[-1] == m_Len && ((uint8_t*)res)[-12] == 0x4 && res[m_Len] == '\0')
					out.emplace_back(reinterpret_cast<ptr_t>(res));
			}

			cstart = res + targetString.size();
		}
	}

	std::string targetString;
	uint32_t m_Len;
};

int main2(int argc, const char** argv)
{
	int pid = atoi(argv[1]);

	std::vector<uint8_t> pattern;

	uint8_t* dataOffset = NULL;

	// input pointer
	ptr_t inputPointer = 0;

	// search pattern
	size_t dataSize = 0;
	int64_t ptrData = 0;
	int32_t intData = 0;
	double doubleData = 0;
	float floatData = 0;

	// search diff
	int searchMode = 0;
	DiffPatternSearchPolicy diffPolicy;
	LuaJIT_v1_1_5_StringSearchPolicy luav115_Policy;
	if (strcmp(argv[2], "-p") == 0)
	{
		searchMode = -1;
		inputPointer = strtoll(argv[3], NULL, 0);
	}
	else if (strcmp(argv[2], "-s") == 0) // string
	{
		dataOffset = (uint8_t*)argv[3];
		dataSize = strlen(argv[3]);
	}
	else if (strcmp(argv[2], "-lld") == 0) // pointer
	{
		ptrData = strtoll(argv[3], NULL, 0);
		dataOffset = (uint8_t*)&ptrData;
		dataSize = sizeof(ptrData);
	}
	else if (strcmp(argv[2], "-d") == 0) // int
	{
		intData = strtol(argv[3], NULL, 0);
		dataOffset = (uint8_t*)&intData;
		dataSize = sizeof(intData);
	}
	else if (strcmp(argv[2], "-df") == 0) // double float
	{
		doubleData = strtod(argv[3], NULL);
		dataOffset = (uint8_t*)&doubleData;
		dataSize = sizeof(doubleData);
	}
	else if (strcmp(argv[2], "-sf") == 0) // single float
	{
		floatData = strtof(argv[3], NULL);
		dataOffset = (uint8_t*)&floatData;
		dataSize = sizeof(floatData);
	}
	else if (strcmp(argv[2], "-diff") == 0)
	{  // TODO: split param by comma
		searchMode = 1;
		diffPolicy.diff1 = strtoll(argv[3], NULL, 0);
		diffPolicy.diff2 = strtoll(argv[4], NULL, 0);
		diffPolicy.diff3 = strtoll(argv[5], NULL, 0);
		if (argc > 6)
		{
			diffPolicy.offset = strtoll(argv[6], NULL, 0);

			if (argc > 7)
			{
				if (strcmp(argv[7], "-s8") == 0)
					diffPolicy.sizeOfPtr = 8;
				else if (strcmp(argv[7], "-s4") == 0)
					diffPolicy.sizeOfPtr = 4;

				if (argc > 8)
				{
					if (strcmp(argv[8], "-noalign") == 0)
						diffPolicy.align = false;
				}
			}
		}

	}
	else if (strcmp(argv[2], "-ls") == 0)
	{
		searchMode = 2;
		luav115_Policy.setTargetString(argv[3]);
	}
// 	else if (strcmp(argv[2], "-lkv") == 0) // find lua k-v pairs by TString*
// 	{
// 
// 	}
	else
	{
		return -1;
	}



	bool memoryDump = false;
	int64_t bias;
	if (argc > 4 && strcmp(argv[4], "-A") == 0)
	{
		memoryDump = true;
		bias = strtoll(argv[5], NULL, 0);
	}

	for (int i = 0; i < dataSize; ++i)
		pattern.push_back(dataOffset[i]);

	// Pattern scanning
	if (Process process; NT_SUCCESS(process.Attach(pid)))
	{
		std::vector<ptr_t> results;

		switch (searchMode)
		{
		case 0:
		{
			PatternSearch ps(pattern);
			ps.SearchRemoteWhole(process, false, 0, results);
			break;
		}
		case 1:
			PatternSearch::SearchRemoteWhole(process, &diffPolicy, results);
			break;
		case 2:
			PatternSearch::SearchRemoteWhole(process, &luav115_Policy, results);
			break;
		}

		if (inputPointer)
		{
			results.push_back(inputPointer);
		}

		for (auto it = results.begin(); it != results.end(); ++it)
		{
			printf("0x%p", (void*)(*it));
			if (memoryDump)
			{ // TODO support more types
				auto res = process.memory().Read<int>((*it) + bias);
				if (res.success())
					printf(" %x", res.result());
				else
					printf(" *");
			}
			printf("\n");

		}
	}
	else
	{
		printf("Attach process failed, check permission.\n");
		return -2;
	}
	return 0;
}

int main( int argc, const char* argv[] )
{
	if (argc > 0)
		return main2(argc, argv);

    // List all process PIDs matching name
    auto pids = Process::EnumByName( L"explorer.exe" );

    // List all process PIDs matching either by PID only
    auto procInfo = Process::EnumByNameOrPID( 0x1234, L"" );

    // List all processes
    auto all = Process::EnumByNameOrPID( 0, L"" );

    // Attach to a process
    if (Process explorer; !pids.empty() && NT_SUCCESS( explorer.Attach( pids.front() ) ))
    {
        auto& core = explorer.core();

        // Get bitness info about this and target processes
        [[maybe_unused]] auto barrier = explorer.barrier();

        // Get process PID and handle
        [[maybe_unused]] auto pid = core.pid();
        [[maybe_unused]] auto handle = core.handle();

        // Get PEB
        PEB_T peb = { };
        [[maybe_unused]] auto peb_ptr = core.peb( &peb );

        // Get all process handles
        if (auto handles = explorer.EnumHandles(); handles)
        {
            // do stuff with handles...
        }
    }

    // Start new suspended process and attach immediately
    Process notepad; 
    notepad.CreateAndAttach( L"C:\\windows\\system32\\notepad.exe", true );
    {
        // do stuff...
        notepad.Resume();
    }

    // Process modules manipulation
    {
        auto& modules = notepad.modules();

        // List all modules (both x86 and x64 for WOW64 processes)
        auto mods = modules.GetAllModules();

        // Get main module (.exe)
        auto mainMod = modules.GetMainModule();

        // Get module base address
        [[maybe_unused]] auto base = mainMod->baseAddress;

        // Get export symbol from module found by name
        auto LoadLibraryWPtr = modules.GetExport( L"kernel32.dll", "LoadLibraryW" );
        if (LoadLibraryWPtr)
        {
        }

        // Unlink module from loader structures
        if (modules.Unlink( mainMod ))
        {
        }
    }

    // Process memory manipulation
    {
        auto& memory = notepad.memory();
        auto mainMod = notepad.modules().GetMainModule();

        //
        // Read memory
        //
        IMAGE_DOS_HEADER dosHeader = { };

        // Method 1
        memory.Read( mainMod->baseAddress, dosHeader );

        // Method 2
        memory.Read( mainMod->baseAddress, sizeof( dosHeader ), &dosHeader );

        // Method 3
        auto[status, dosHeader2] = memory.Read<IMAGE_DOS_HEADER>( mainMod->baseAddress );

        // Change memory protection
        if (NT_SUCCESS( memory.Protect( mainMod->baseAddress, sizeof( dosHeader ), PAGE_READWRITE ) ))
        {
            //
            // Write memory
            //

            // Method 1
            memory.Write( mainMod->baseAddress, dosHeader );

            // Method 2
            memory.Write( mainMod->baseAddress, sizeof( dosHeader ), &dosHeader );
        }

        // Allocate memory
        if (auto[status2, block] = memory.Allocate( 0x1000, PAGE_EXECUTE_READWRITE ); NT_SUCCESS( status2 ))
        {
            // Write into memory block
            block->Write( 0x10, 12.0 );

            // Read from memory block
            [[maybe_unused]] auto dval = block->Read<double>( 0x10, 0.0 );
        }

        // Enumerate regions
        auto regions = memory.EnumRegions();
    }

    // Threads manipulation
    {
        // Get all thread
        auto threads = notepad.threads().getAll();

        // Get main thread
        auto mainThread = notepad.threads().getMain();

        // Get thread by TID
        auto thread = notepad.threads().get( mainThread->id() );

        // Get context
        CONTEXT_T ctx = { };
        if (thread->GetContext( ctx, CONTEXT_FLOATING_POINT ))
        {
            // Set context
            thread->SetContext( ctx );
        }

        // Wait for thread exit
        thread->Join( 100 );
    }

    // JIT Assembler
    if (auto asmPtr = AsmFactory::GetAssembler())
    {
        auto& a = *asmPtr;

        a.GenPrologue();
        a->add( a->zcx, a->zdx );
        a->mov( a->zax, a->zcx );
        a.GenEpilogue();

        auto func = reinterpret_cast<uintptr_t( __fastcall* )(uintptr_t, uintptr_t)>(a->make());
        [[maybe_unused]] uintptr_t r = func( 10, 5 );
    }

    // Remote code execution
    {
        auto& remote = notepad.remote();
        remote.CreateRPCEnvironment( Worker_None, true );
        
        auto GetModuleHandleWPtr = notepad.modules().GetExport( L"kernel32.dll", "GetModuleHandleW" );
        if (GetModuleHandleWPtr)
        {
            // Direct execution in the new thread without stub
            [[maybe_unused]] DWORD mod = remote.ExecDirect( GetModuleHandleWPtr->procAddress, 0 );
        }

        // Execute in the new thread using stub
        if (auto asmPtr = AsmFactory::GetAssembler(); asmPtr && GetModuleHandleWPtr)
        {
            auto& a = *asmPtr;

            a.GenPrologue();
            a.GenCall( static_cast<uintptr_t>(GetModuleHandleWPtr->procAddress), { nullptr }, cc_stdcall );
            a.GenEpilogue();

            uint64_t result = 0;
            remote.ExecInNewThread( a->make(), a->getCodeSize(), result );
        }

        // Execute in main thread
        auto mainThread = notepad.threads().getMain();
        if (auto asmPtr = AsmFactory::GetAssembler(); asmPtr && mainThread && GetModuleHandleWPtr)
        {
            auto& a = *asmPtr;

            a.GenPrologue();
            a.GenCall( static_cast<uintptr_t>(GetModuleHandleWPtr->procAddress), { nullptr }, cc_stdcall );
            a.GenEpilogue();

            uint64_t result = 0;
            remote.ExecInAnyThread( a->make(), a->getCodeSize(), result, mainThread );
        }
    }

    // Pattern scanning
    if (Process process; NT_SUCCESS( process.Attach( GetCurrentProcessId() ) ))
    {
        PatternSearch ps{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

        std::vector<ptr_t> results;
        ps.SearchRemoteWhole( process, false, 0, results );
    }

    // Remote function calls
    {
        // Simple direct invocation
        if (auto pMessageBoxW = MakeRemoteFunction<decltype(&MessageBoxW)>( notepad, L"user32.dll", "MessageBoxW" ))
        {
            auto result = pMessageBoxW( HWND_DESKTOP, L"Hello world!", L"Title", MB_OKCANCEL );
            if (*result == IDCANCEL)
            {
            }
        }

        // Call in specific thread
        auto mainThread = notepad.threads().getMain();
        if (auto pIsGUIThread = MakeRemoteFunction<decltype(&IsGUIThread)>( notepad, L"user32.dll", "IsGUIThread" ); pIsGUIThread && mainThread)
        {
            auto result = pIsGUIThread.Call( { FALSE }, mainThread );
            if (*result)
            {
            }
        }

        // Complex args
        if (auto pMultiByteToWideChar = MakeRemoteFunction<decltype(&MultiByteToWideChar)>( notepad, L"kernel32.dll", "MultiByteToWideChar" ))
        {
            auto args = pMultiByteToWideChar.MakeArguments( { CP_ACP, 0, "Sample text", -1, nullptr, 0 } );
            std::wstring converted( 32, L'\0' );

            // Set buffer pointer and size manually
            args.set( 4, AsmVariant( converted.data(), converted.size() * sizeof( wchar_t ) ) );
            args.set( 5, converted.size() );

            auto length = pMultiByteToWideChar.Call( args );
            if (length)
                converted.resize( *length - 1 );
        }
    }

    // Direct syscalls, currently works for x64 only
    {
        uint8_t buf[32] = { };
        uintptr_t bytes = 0;

        NTSTATUS status = syscall::nt_syscall(
            syscall::get_index( "NtReadVirtualMemory" ),
            GetCurrentProcess(),
            GetModuleHandle( nullptr ),
            buf,
            sizeof(buf),
            &bytes
        );

        if (NT_SUCCESS( status ))
        {
        }
    }

    notepad.Terminate();

    // Manual mapping. See following functions for more info
    MapCalcFromFile();
    MapCmdFromMem();

    return 0;
}