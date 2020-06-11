
//
//  include.h
//  hook
//
//  Created by Weiteng Chen on 6/7/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#ifndef include_h
#define include_h

#include <libkern/libkern.h>

#define DRIVER_NAME "Hook"
#define DO_LOG  1

typedef struct entry {
    // externalMethod
    uint32_t connection;
    uint32_t selector;
    uint64_t *input;
    uint64_t *output;
    // function
    unsigned int index;
} Entry;

#define MAX_ENTRY  512
Entry entries[MAX_ENTRY];
// FIXME: How to deal with multi threads
unsigned int gEntryIndex = 0;
unsigned int gLastIndex = 0;

typedef intptr_t(*syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef struct hooker {
    syscall_t originFunc;
    syscall_t hookFunc;
} Hooker;

Hooker gHookers[512] = {0};
Hooker gExternalMethod;
volatile unsigned int gEnableHook = 0;

#define DeclareStub(ID)                  \
static long _stub_func_##ID(             \
    volatile long arg0, volatile long arg1, \
    volatile long arg2, volatile long arg3, \
    volatile long arg4, volatile long arg5, \
    volatile long arg6, volatile long arg7, \
    volatile long arg8, volatile long arg9) \
{                                           \
    if (gEnableHook) {                      \
        printf("[%s.kext] function %d is called\n", DRIVER_NAME, ID);         \
        entries[gLastIndex].index = ID;                                       \
    }                                                                         \
    return gHookers[ID].originFunc(arg0, arg1, arg2, arg3, arg4, arg5, arg6,  \
        arg7, arg8, arg9);  \
}
#define GetHookStub(ID) (&_stub_func_##ID)
#define RegisterStub(ID) gHookers[ID].hookFunc = GetHookStub(ID)

//
// Enable and disable interrupts
//

#define disable_interrupts() __asm__ volatile ("cli");
#define enable_interrupts() __asm__ volatile ("sti");

// see <IOKit/IOUserClient.h>
struct IOExternalMethodArguments {
    uint32_t            version;

    uint32_t            selector;

    mach_port_t           asyncWakePort;
    void * asyncReference;
    uint32_t              asyncReferenceCount;

    const uint64_t *    scalarInput;
    uint32_t            scalarInputCount;

    void *              structureInput;
    uint32_t            structureInputSize;

    void * structureInputDescriptor;

    uint64_t *          scalarOutput;
    uint32_t            scalarOutputCount;

    void *              structureOutput;
    uint32_t            structureOutputSize;

    void * structureOutputDescriptor;
    uint32_t             structureOutputDescriptorSize;

    uint32_t            __reservedA;

    void **         structureVariableOutputData;

    uint32_t            __reserved[30];
};

#endif /* include_h */
