
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

#include "common.h"

#define DRIVER_NAME "Hook"
#define DO_LOG  1


#define ENCODE_PTR(ptr, size, opt) (ptr | (size << 48) | (opt << 60))
#define GET_PTR(ptr) (ptr & 0xffffffffffff)
#define GET_SIZE(ptr) ((ptr >> 48) & 0xfff)
#define GET_OPT(ptr) ((ptr >> 60) & 0xf)

// FIXME: How to deal with multi threads
unsigned int gEntryIndex = 0;
unsigned int gLastIndex = 0;

typedef intptr_t(*syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef struct hooker {
    syscall_t originFunc;
    syscall_t hookFunc;
} Hooker;

// Hook functions
Hooker gHookers[512] = {0};
Hooker gExternalMethod = {0};
Hooker gWithAddressRange = {0};
unsigned gHookMode = HOOK_MODE_NONE;

// controller related (only one process)
struct kern_ctl_reg gKeCtlReg = {0};
kern_ctl_ref gKeCtlRef = NULL;
unsigned int gKeCtrlConnected = 0;
unsigned int gkeCtlSacUnit = 0;
int gPid = 0;

#if DO_LOG
bool gDoLog = true;
#else
bool gDoLog = false;
#endif

void send_routine(unsigned index) {
    gRoutineCmd.header.type = HOOK_ROUNTINE;
    gRoutineCmd.header.size = sizeof(CMD_ROUTINE) - sizeof(CMD_HEADER);
    gRoutineCmd.index = index;
    if (ctl_enqueuedata(gKeCtlRef, gkeCtlSacUnit, &gRoutineCmd, sizeof(gRoutineCmd), 0)) {
        printf("enqueue routine error\n");
    }
}

#define DeclareStub(ID)                  \
static long _stub_func_##ID(             \
    volatile long arg0, volatile long arg1, \
    volatile long arg2, volatile long arg3, \
    volatile long arg4, volatile long arg5, \
    volatile long arg6, volatile long arg7, \
    volatile long arg8, volatile long arg9) \
{                                           \
    if (gPid == proc_selfpid()) {           \
        if (gDoLog) printf("[%s.kext] function %d is called\n", DRIVER_NAME, ID);      \
        if (gHookMode == HOOK_MODE_RECORD) {                                           \
            entries[gLastIndex].index = ID;                                            \
        } else if (gHookMode == HOOK_MODE_LISTEN)                                      \
            send_routine(ID);                                                          \
    }                                                                                  \
    return gHookers[ID].originFunc(arg0, arg1, arg2, arg3, arg4, arg5, arg6,           \
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
