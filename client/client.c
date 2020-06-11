//
//  client.c
//  hook
//
//  Created by Weiteng Chen on 6/9/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>

#include "client.h"

#define HOOK_CTL_NAME   "com.wchen130.hook"

#define SOCKOPT_SET_ENABLE     1
#define SOCKOPT_SET_DISABLE    2
#define SOCKOPT_SET_RESET      3

#define SOCKOPT_GET_TEST       1

int main() {
    struct sockaddr_ctl addr;
    bzero(&addr, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd == -1) {
        perror("Error with socket\n");
        exit(-1);
    }
    
    struct ctl_info info;
    bzero(&info, sizeof(info));
    strncpy(info.ctl_name, HOOK_CTL_NAME, sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info)) {
        perror("Could not get ID for kernel control.\n");
        exit(-1);
    }
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;
    
    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc) {
        printf("connect failed %d\n", rc);
        exit(-1);
    }
    
    uint64_t funcs[0xd5];
    unsigned int len = 0xd5 * sizeof(uint64_t);
    rc = getsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_GET_TEST, funcs, &len);
    if (rc == 0) {
        for (int i = 0; i < 0xd5; i++) {
            printf("%d: 0x%llx\n", i, funcs[i]);
        }
    }
    char buffer[0x100];
    if (send(fd, buffer, 0x10, 0) == -1) {
        perror("fail to send\n");
    }
    
    shutdown(fd, SHUT_RDWR);
    return 0;
}
