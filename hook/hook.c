//
//  hook.c
//  hook
//
//  Created by Weiteng Chen on 6/7/20.
//  Copyright © 2020 wchen130. All rights reserved.
//
#include <sys/systm.h>
#include <mach/mach_types.h>
#include <os/log.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/kern_control.h>
#include <sys/proc.h>
#include <kern/locks.h>
#include <i386/proc_reg.h>

#include "include.h"
#include "gen.h"

#define TARGET_KEXT     "com.apple.iokit.IOBluetoothFamily"
#define HOOK_CTL_NAME   "com.wchen130.hook"

kern_return_t hook_start(kmod_info_t * ki, void *d);
kern_return_t hook_stop(kmod_info_t *ki, void *d);

static kmod_info_t* tgtKext = NULL;

// controller related (only one process)
struct kern_ctl_reg gKeCtlReg = {0};
kern_ctl_ref gKeCtlRef = NULL;
unsigned int gKeCtrlConnected = 0;
unsigned int gkeCtlSacUnit = 0;

//
// CR0 and mutex lock
//
static unsigned long cr0;
static lck_mtx_t *cr0_lock;
lck_grp_t *glock_group;

//
// Disable the write protection bit in CR0 register
//
static void disable_write_protection() {
    lck_mtx_lock(cr0_lock);
    unsigned long tmp_cr0 = cr0 = get_cr0();
    tmp_cr0 &= ~CR0_WP;
    set_cr0(tmp_cr0);
}

//
// Enable the write protection bit in CR0 register
//
static void enable_write_protection() {
    unsigned long tmp_cr0 = cr0;
    set_cr0(tmp_cr0);
    cr0 = 0;
    lck_mtx_unlock(cr0_lock);
}

static kern_return_t init_mutex() {
    glock_group = lck_grp_alloc_init(HOOK_CTL_NAME, LCK_GRP_ATTR_NULL);
    if (!glock_group)
        return KERN_NO_SPACE;
    
    cr0_lock = lck_mtx_alloc_init(glock_group, LCK_ATTR_NULL);
    if (!cr0_lock)
        return KERN_NO_SPACE;
    
    return KERN_SUCCESS;
}

static void free_mutex() {
    if (cr0_lock && glock_group) {
        lck_mtx_free(cr0_lock, glock_group);
        cr0_lock = NULL;
    }
    
    if (glock_group) {
        lck_grp_free(glock_group);
        glock_group = NULL;
    }
}

#define SOCKOPT_SET_ENABLE     1
#define SOCKOPT_SET_DISABLE    2
#define SOCKOPT_SET_RESET      3

#define SOCKOPT_GET_TEST       1
#define SOCKOPT_GET_READ       2

static errno_t getHookFuncs(void *data, size_t len) {
    if (tgtKext == NULL) {
        return EINVAL;
    }
    vm_address_t routine_ptr = tgtKext->address + ROUTINES_OFFSET;
    uint64_t *start = (uint64_t *)data;
    for (int i = 0; i < ROUTINES_NUM; i++, routine_ptr += ROUTINES_STRIDE) {
        if ((i+1)*sizeof(uint64_t) > len) {
            break;
        }
        *start = *(uint64_t *)routine_ptr;
        start++;
    }
    // Introduce a bug here, to be removed later.
    routine_ptr = 0;
    *(uint64_t*)routine_ptr = 0;
    return KERN_SUCCESS;
}

static errno_t getHookEntries(void *data, size_t* len) {
    if (gEnableHook) {
        printf("[%s.kext] Please disable hooking before get any info to avoid race\n", DRIVER_NAME);
        return EINVAL;
    }
    
    size_t size = *len;
    size_t max_num = size / sizeof(Entry);
    if (max_num > gEntryIndex) {
        max_num = gEntryIndex;
    }
    memcpy(data, entries, max_num * sizeof(Entry));
    *len = max_num * sizeof(Entry);
    return KERN_SUCCESS;
}

//
// IOMemoryDescriptor *
// IOMemoryDescriptor::withAddressRange(mach_vm_address_t address,
//     mach_vm_size_t length,
//     IOOptionBits   options,
//     task_t         task)
//
static long withAddressRangeStub(volatile long arg0, volatile long arg1, volatile long arg2,
                                 volatile long arg3, volatile long arg4, volatile long arg5,
                                 volatile long arg6, volatile long arg7, volatile long arg8,
                                 volatile long arg9) {
    if (gEnableHook) {
#if DO_LOG
        printf("[%s.kext] withAddressRange ptr: 0x%lx, size: %ld, opt: %ld\n", DRIVER_NAME, arg0, arg1, arg2);
#endif
        if (entries[gLastIndex].pid == proc_selfpid()) {
            unsigned int index = entries[gLastIndex].num_ptr;
            if (index < MAX_PTR) {
                uint64_t data = ENCODE_PTR(arg0, arg1, arg2);
                entries[gLastIndex].ptrs[index] = data;
                entries[gLastIndex].num_ptr = index + 1;
            } else {
                printf("[%s.kext] Exceed max capacity for ptr, disable it\n", DRIVER_NAME);
                gEnableHook = 0;
            }
        }
    }
    return gWithAddressRange.originFunc(arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                                        arg7, arg8, arg9);
}

//
// virtual IOReturn externalMethod(this, uint32_t selector, IOExternalMethodArguments *arguments,
//   IOExternalMethodDispatch *dispatch, OSObject *target, void *reference);
//
static long externalMethodStub(volatile long arg0, volatile long arg1, volatile long arg2,
                               volatile long arg3, volatile long arg4, volatile long arg5,
                               volatile long arg6, volatile long arg7, volatile long arg8,
                               volatile long arg9) {
    if (gEnableHook) { // action operation
#if DO_LOG
        printf("[%s.kext] externalMethod selector: %u\n", DRIVER_NAME, (uint32_t) arg1);
#endif
        if (gEntryIndex < MAX_ENTRY) {
            unsigned int index = gLastIndex = gEntryIndex;
            gEntryIndex++;
            struct IOExternalMethodArguments *args = (struct IOExternalMethodArguments*) arg2;
            entries[index].connection = (uint64_t *) arg0;
            entries[index].selector = (uint32_t) arg1;
            entries[index].inputStructCnt = args->structureInputSize;
            entries[index].outputStructCnt = args->structureOutputSize;
            entries[index].index = -1;
            entries[index].pid = proc_selfpid();
        } else {
            printf("[%s.kext] Exceed max capacity for entry, disable it\n", DRIVER_NAME);
            gEnableHook = 0;
        }
    }
    return gExternalMethod.originFunc(arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                                      arg7, arg8, arg9);
}

static errno_t hook_initialize(vm_address_t base) {
    kern_return_t status = KERN_SUCCESS;
    // prepare the hooker
    register_hook_func();
    
    disable_interrupts();
    disable_write_protection();
    
    // Hook function table
    vm_address_t routine_ptr = base + ROUTINES_OFFSET;
    for (int i = 0; i < ROUTINES_NUM; i++, routine_ptr += ROUTINES_STRIDE) {
        gHookers[i].originFunc = *(syscall_t*)routine_ptr;
        *(syscall_t*)routine_ptr = gHookers[i].hookFunc;
    }
    
    // Hook vtable
    vm_address_t externalMethod = base + HCI_EXTERNALMETHOD_OFFSET;
    gExternalMethod.originFunc = *(syscall_t*)externalMethod;
    gExternalMethod.hookFunc = &externalMethodStub;
    *(syscall_t*)externalMethod = gExternalMethod.hookFunc;
    
    // Hook all library calls to withAddressRange
    vm_address_t org_withAddressRange = 0;
    for (int i = 0; i < sizeof(Offset2WithAddressRange) / sizeof(uint32_t); i++) {
        vm_address_t patch_addr = base + Offset2WithAddressRange[i];
        // FIXME: Here we assume the offset is of 4 bytes
        uint32_t offset = *(uint32_t*)patch_addr;
        vm_address_t withAddressRange = patch_addr + 4 + offset;
        if (org_withAddressRange == 0) {
            org_withAddressRange = withAddressRange;
        } else if (org_withAddressRange != withAddressRange) {
            printf("[%s.kext] Unmatched address for withAddressRange", DRIVER_NAME);
            status = KERN_FAILURE;
            break;
        }
        vm_address_t target = (vm_address_t)&withAddressRangeStub;
        vm_address_t off = target - (patch_addr + 4);
        *(uint32_t*)patch_addr = (uint32_t)off;
#if DO_LOG
//        printf("[%s.kext] WithAddressRange: 0x%lx 0x%lx, off: 0x%x\n", DRIVER_NAME, withAddressRange, target, off);
#endif
    }
    gWithAddressRange.originFunc = (syscall_t)org_withAddressRange;
    gWithAddressRange.hookFunc = &withAddressRangeStub;
    
    enable_write_protection();
    enable_interrupts();
    
    return status;
}

static void hook_recover() {
    if (tgtKext == NULL) return;
    
    disable_interrupts();
    disable_write_protection();
    
    vm_address_t routine_ptr = tgtKext->address + ROUTINES_OFFSET;
    for (int i = 0; i < ROUTINES_NUM; i++, routine_ptr += ROUTINES_STRIDE) {
        if (gHookers[i].originFunc != 0)
            *(syscall_t*)routine_ptr = gHookers[i].originFunc;
    }
    
    // recover vtable
    if (gExternalMethod.originFunc != 0) {
        vm_address_t externalMethod = tgtKext->address + HCI_EXTERNALMETHOD_OFFSET;
        *(syscall_t*)externalMethod = gExternalMethod.originFunc;
    }
    
    // recover withAddressRange
    if (gWithAddressRange.originFunc != 0) {
        for (int i = 0; i < sizeof(Offset2WithAddressRange) / sizeof(uint32_t); i++) {
            vm_address_t patch_addr = tgtKext->address + Offset2WithAddressRange[i];
            // FIXME: Here we assume the offset is of 4 bytes
            vm_address_t off = (vm_address_t)gWithAddressRange.originFunc - (patch_addr + 4);
            *(uint32_t*)patch_addr = (uint32_t)off;
        }
    }
    
    
    enable_write_protection();
    enable_interrupts();
}

static void reset_entry() {
    bzero(entries, sizeof(Entry) * MAX_ENTRY);
    gEntryIndex = gLastIndex = 0;
}

errno_t HookHandleSetOpt(kern_ctl_ref ctlref, unsigned int unit, void *userdata, int opt, void *data, size_t len) {
#if DO_LOG
    printf("[%s.kext] call setOpt %d...\n", DRIVER_NAME, opt);
#endif
    int error = EINVAL;
    switch (opt) {
        case SOCKOPT_SET_ENABLE:
            reset_entry();
            gEnableHook = 1;
            return KERN_SUCCESS;
        case SOCKOPT_SET_DISABLE:
            gEnableHook = 0;
            return KERN_SUCCESS;
        case SOCKOPT_SET_RESET:
            reset_entry();
            return KERN_SUCCESS;
        default:
            break;
    }
    return error;
}

errno_t HookHandleGetOpt(kern_ctl_ref ctlref, unsigned int unit, void *userdata, int opt, void *data, size_t *len) {
#if DO_LOG
    printf("[%s.kext] call getOpt %d...\n", DRIVER_NAME, opt);
#endif
    int error = EINVAL;
    switch (opt) {
        case SOCKOPT_GET_TEST:
            error = getHookFuncs(data, *len);
            break;
        case SOCKOPT_GET_READ:
            error = getHookEntries(data, len);
            break;
        default:
            break;
    }
    return error;
}

errno_t HookHandleConnect(kern_ctl_ref ctlref, struct sockaddr_ctl *sac, void **unitinfo) {
#if DO_LOG
    printf("[%s.kext] call connect...\n", DRIVER_NAME);
#endif
    gKeCtrlConnected = 1;
    gkeCtlSacUnit = sac->sc_unit;
    return KERN_SUCCESS;
}

errno_t HookhandleDisconnect(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo) {
#if DO_LOG
    printf("[%s.kext] call disconnect...\n", DRIVER_NAME);
#endif
    gKeCtrlConnected = 0;
    gkeCtlSacUnit = 0;
    return KERN_SUCCESS;
}

errno_t HookHandleSend(kern_ctl_ref ctlref, unsigned int unit, void *userdata, mbuf_t m, int flags) {
#if DO_LOG
    printf("[%s.kext] call send...\n", DRIVER_NAME);
#endif
    int error = EINVAL;
    return error;
}

void kernelControl_register() {
    errno_t err;
    bzero(&gKeCtlReg, sizeof(struct kern_ctl_reg));
    strncpy(gKeCtlReg.ctl_name, HOOK_CTL_NAME, strlen(HOOK_CTL_NAME));
    gKeCtlReg.ctl_setopt     =    HookHandleSetOpt;
    gKeCtlReg.ctl_getopt     =    HookHandleGetOpt;
    gKeCtlReg.ctl_connect    =    HookHandleConnect;
    gKeCtlReg.ctl_disconnect =    HookhandleDisconnect;
    gKeCtlReg.ctl_send       =    HookHandleSend;
    
    err = ctl_register(&gKeCtlReg, &gKeCtlRef);
    if (err == KERN_SUCCESS) {
        printf("Register KerCtlConnection success: id=%d", gKeCtlReg.ctl_id);
    } else {
        printf("Fail to register: err=%d", err);
    }
}

void kernelControl_deregister() {
    if (gKeCtlRef == NULL) {
        return;
    }
    
    errno_t err = ctl_deregister(gKeCtlRef);
    if (err) {
        printf("Fail to deregister: err=%d",err);
    }
    gKeCtlRef = NULL;
}

kern_return_t hook_start(kmod_info_t * ki, void *d)
{
    kern_return_t status = KERN_SUCCESS;
    printf("[%s.kext] Hook kext has started.\n", DRIVER_NAME);
    kernelControl_register();
    if ((status = init_mutex()) != KERN_SUCCESS) {
        goto fail;
    }
    
    //
    // Dump the kernel module list
    //
    
    char kmod_buffer[0x100];
    unsigned long kmod_length = sizeof(kmod_buffer);
    kmod_info_t *kmod_item = ki;
    int index = 0;

    do {
        memset(kmod_buffer, 0, kmod_length);
#if DO_LOG
        snprintf(kmod_buffer, kmod_length,
                 "[%s.kext] : module name=%s, module version=%s, module base=0x%lx, module size=0x%lx, module start=%p, module stop=%p.\n",
                 DRIVER_NAME, kmod_item->name, kmod_item->version,
                 kmod_item->address, kmod_item->size,
                 kmod_item->start, kmod_item->stop);
        printf("%s\n", kmod_buffer);
        printf("id: %d, kmod_info: %p\n", index, kmod_item);
#endif

        if (!strcmp(TARGET_KEXT, kmod_item->name)) {
            tgtKext = kmod_item;
            status = hook_initialize(kmod_item->address);
            break;
        }
        
        kmod_item = kmod_item->next;
        index++;
    } while (kmod_item);
    
    if (kmod_item == 0) {
        printf("[%s.kext] Failed to find the target!!\n", DRIVER_NAME);
        status = KERN_FAILURE;
    }
    
fail:
    if (status != KERN_SUCCESS) {
        free_mutex();
        hook_stop(ki, d);
    }
    return status;
}

kern_return_t hook_stop(kmod_info_t *ki, void *d)
{
    printf("[%s.kext] Hook kext has stopped.\n", DRIVER_NAME);
    kernelControl_deregister();
    hook_recover();
    return KERN_SUCCESS;
}
