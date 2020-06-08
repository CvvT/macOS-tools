//
//  hook.c
//  hook
//
//  Created by 陈伟腾 on 6/7/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#include <mach/mach_types.h>

kern_return_t hook_start(kmod_info_t * ki, void *d);
kern_return_t hook_stop(kmod_info_t *ki, void *d);

kern_return_t hook_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t hook_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
