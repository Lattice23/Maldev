#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <print>

#define FAIL(function) printf("%s ERROR: %d\n", function, GetLastError() );
#define PTR_ADD_OFFSET( Pointer,Offset )((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))


PVOID GetImportDescriptor( PVOID buffer )
{
  PIMAGE_DATA_DIRECTORY  pImports   =  NULL;

  // ?
  pImports = static_cast<PIMAGE_DATA_DIRECTORY>( &static_cast<PIMAGE_OPTIONAL_HEADER>( &static_cast<PIMAGE_NT_HEADERS>( PTR_ADD_OFFSET( buffer, reinterpret_cast<PIMAGE_DOS_HEADER>( buffer )->e_lfanew ) )->OptionalHeader )->DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ] );
  
  return PTR_ADD_OFFSET( buffer, pImports->VirtualAddress );
}


PULONG_PTR GetTargetFunc( PVOID buffer, std::string Target, PIMAGE_IMPORT_DESCRIPTOR DLL ){

  PIMAGE_THUNK_DATA        ILT      = NULL,
                           IAT      = NULL;

  PCHAR                    DllName  = NULL;  

  while ( DLL->OriginalFirstThunk != NULL ){

    ILT = reinterpret_cast<PIMAGE_THUNK_DATA>( PTR_ADD_OFFSET( buffer, DLL->OriginalFirstThunk ) );
    IAT = reinterpret_cast<PIMAGE_THUNK_DATA>( PTR_ADD_OFFSET( buffer, DLL->FirstThunk ) );

    DllName = reinterpret_cast<PCHAR>( PTR_ADD_OFFSET( buffer, DLL->Name ) );
    HMODULE pLibrary = NULL;

    if ( pLibrary = LoadLibrary( DllName ); pLibrary == NULL ){
      FAIL("LoadLibrary");
      return nullptr;
    }

    while ( ILT->u1.Function != NULL ){

       if (! ( ILT->u1.Ordinal & IMAGE_ORDINAL_FLAG) ){
           
            PIMAGE_IMPORT_BY_NAME pFunction =reinterpret_cast<PIMAGE_IMPORT_BY_NAME>( PTR_ADD_OFFSET( buffer, ILT->u1.AddressOfData ) );

            PCHAR FuncName = pFunction->Name;

            if (! strcmp( FuncName, Target.c_str() ) ){
              FARPROC FuncAddress =  GetProcAddress( pLibrary, FuncName );
              
              std::print("Target Found in {}\n", DllName);
              return reinterpret_cast<PULONG_PTR>( &IAT->u1.Function );
            }
      }
      ( ILT++,IAT++ );
    }
    DLL++;
  }
  std::print("Failed to retrieve Target Address\n");
  SetLastError( ERROR_INVALID_HANDLE );
  return nullptr;
}

int FakeFunc(HWND hwnd, LPCTSTR lptext, LPCTSTR lpCaption, UINT uType){
  
  std::cout << "HOOK BEEP :)\n";
  Beep(700,6000);
  return 0;
}

void Actual(){
  MessageBoxW( NULL, L"Normal", L"Normal", MB_ABORTRETRYIGNORE );
}

int main(){
  using fake = int(*)(HWND hwnd, LPCTSTR lptext, LPCTSTR lpCaption, UINT uType); 
  PIMAGE_IMPORT_DESCRIPTOR DLL            = NULL; 
  PULONG_PTR               buffer         = NULL,
                           TargetAddress  = NULL;
  std::string              TargetFunction = "MessageBoxA";


  // Get Main buffer
  if ( buffer = reinterpret_cast<PULONG_PTR>( GetModuleHandleA( NULL ) ) ; buffer == NULL) {
    FAIL("GetModuleHandleA");
    return 1;
  }

  std::print("Got base address {}\n", static_cast<PVOID>( buffer ) ) ;
  
  // Get import table
  if ( DLL = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>( GetImportDescriptor( buffer ) ); DLL == NULL ){
    FAIL("GetImportDescriptor");
    return 1;
  }

    
  // Find the target function address 
  if ( TargetAddress = GetTargetFunc( buffer, TargetFunction, DLL ); TargetAddress == NULL ){
    FAIL("GetTargetFunc");
    return 1;
  }
  std::print("{} ---> {}\n", TargetFunction, (PVOID)TargetAddress);
  
  std::print("Running Normal {}\n", TargetFunction);
  WaitForSingleObject( CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&Actual,NULL,0,NULL), 2000);
  
  //Change permisions 
  DWORD dwOld;
  if (! VirtualProtect( TargetAddress, sizeof(TargetAddress), PAGE_EXECUTE_READWRITE, &dwOld ) ){
        FAIL("VirtualProtect");
        return 1;
      }

  // Switch the real entry with the fake
  *TargetAddress = (ULONG_PTR)&FakeFunc;

  if (! VirtualProtect( TargetAddress, sizeof(TargetAddress), dwOld, &dwOld ) ){
        FAIL("VirtualProtect");
  }

  std::print("Running Hooked {}\n", TargetFunction);
  MessageBoxA( NULL, "LOL", "LOL", MB_ABORTRETRYIGNORE );
}
