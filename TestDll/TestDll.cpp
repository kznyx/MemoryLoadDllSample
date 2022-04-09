// TestDll.cpp : Defines the exported functions for the DLL.
//

#include "framework.h"
#include "TestDll.h"


// This is an example of an exported variable
TESTDLL_API int nTestDll=0;

// This is an example of an exported function.
TESTDLL_API int fnTestDll(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CTestDll::CTestDll()
{
    return;
}
