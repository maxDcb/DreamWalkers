#include "syscall.hpp"


DWORD GlobalHash = 0x0;


EXTERN_C DWORD getGlobalHash()
{
    return GlobalHash;
}


DWORD SW3_HashSyscall(const char *FunctionName)
{
    DWORD Hash = 0x811C9DC5; // FNV offset basis
    DWORD FNV_prime = 0x01000193; // FNV prime

    int c;
    while (c = *FunctionName++) 
    {
        Hash ^= c;                 // XOR the byte into the lowest byte of the hash
        Hash *= FNV_prime;          // Multiply by FNV prime
    }

    return Hash & 0xFFFFFFFF;       // Ensure the result is a 32-bit hash
}

bool compareEntry(Entry i1, Entry i2) 
{ 
    return (i1.getAddress() < i2.getAddress()); 
} 

SyscallList* SyscallList::singleton_= nullptr;


SyscallList *SyscallList::GetInstance()
{
    if(singleton_==nullptr){
        singleton_ = new SyscallList();
    }
    return singleton_;
}


EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
    SyscallList* singleton = SyscallList::GetInstance();
    return singleton->getSyscallNumber(FunctionHash);
}


EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
    SyscallList* singleton = SyscallList::GetInstance();
    return singleton->getSyscallAddress(FunctionHash);
}

