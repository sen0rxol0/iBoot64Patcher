//
//  main.cpp
//  iBoot64Patcher
//
//  Created by tihmstar on 27.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//
//  Edited by @sen0rxol0 on 29.06.25.
//
// Added libpatchfinder instead of liboffsetfinder64
// Fixed build in Actions
// Added and fixed get_freshnonce_patch(), thanks to Cryptiiiic's fork
// Added input file reading into a buffer
// Improved file read and write code

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
//#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder32.hpp>
#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder64.hpp>

#define HAS_ARG(x,y) (!strcmp(argv[i], x) && (i + y) < argc)

using namespace tihmstar::patchfinder;

#define FLAG_UNLOCK_NVRAM (1 << 0)

int main(int argc, const char * argv[]) {
    
    if(argc < 3) {
        printf("Usage: %s <iboot_in> <iboot_out> [args]\n", argv[0]);
        printf("\t-b <str>\tApply custom boot args.\n");
        printf("\t-c <cmd> <ptr>\tChange a command handler's pointer (hex).\n");
        printf("\t-n \t\tApply unlock nvram patch.\n");
        return -1;
    }
    
    printf("%s: Starting...\n", __FUNCTION__);

    char* cmd_handler_str = NULL;
    char* custom_boot_args = NULL;
    uint64_t cmd_handler_ptr = 0;
    int flags = 0;
    
    for(int i = 0; i < argc; i++) {
        if(HAS_ARG("-b", 1)) {
            custom_boot_args = (char*) argv[i+1];
        } else if(HAS_ARG("-n", 0)) {
            flags |= FLAG_UNLOCK_NVRAM;
        }else if(HAS_ARG("-c", 2)) {
            cmd_handler_str = (char*) argv[i+1];
            sscanf((char*) argv[i+2], "0x%016llX", &cmd_handler_ptr);
        }
    }
    
    const char *input_path = argv[1];
    const char *output_path = argv[2];

    FILE *fp = nullptr;

    /* Read decrypted input file into buffer... */
    fp = fopen(input_path, "rb+");
    
    if (!fp) {
        printf("Unable to open %s!\n", input_path);
        return -1;
    }

    struct stat st{0};
    
    if (stat(input_path, &st) < 0) {
        printf("Error getting size for %s!\n", input_path);
        return -1;
    }

    size_t buf_size = st.st_size;
    void *iboot_buf = (void *) malloc(buf_size);
    
    if (!iboot_buf) {
        printf("Out of memory while allocating region for %s!\n", input_path);
        fclose(fp);
        return -1;
    }

    fread(iboot_buf, 1, buf_size, fp);
    fclose(fp);
    
    ibootpatchfinder *ibpf = ibootpatchfinder64::make_ibootpatchfinder64(iboot_buf, buf_size);

    std::vector<patch> patches;
    
    /* Check to see if the loader has a kernel load routine before trying to apply custom boot args + debug-enabled override. */
    if(ibpf->has_kernel_load()) {
        if(custom_boot_args) {
            try {
                printf("getting get_boot_arg_patch(%s) patch\n", custom_boot_args);
                auto patch = ibpf->get_boot_arg_patch(custom_boot_args);
                patches.insert(patches.begin(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                printf("Error doing patch_boot_args()!\n");
                return -1;
            }
        }
        
        
        /* Only bootloaders with the kernel load routines pass the DeviceTree. */
        try {
            printf("getting get_debug_enabled_patch() patch\n");
            auto patch = ibpf->get_debug_enabled_patch();
            patches.insert(patches.begin(), patch.begin(), patch.end());
        } catch (...) {
            printf("Error doing patch_debug_enabled()!\n");
            return -1;
        }
    }
    
    /* Ensure that the loader has a shell. */
    if(ibpf->has_recovery_console()) {
        if (cmd_handler_str && cmd_handler_ptr) {
            try {
                printf("getting get_cmd_handler_patch(%s,0x%016llx) patch\n", cmd_handler_str,cmd_handler_ptr);
                auto patch = ibpf->get_cmd_handler_patch(cmd_handler_str, cmd_handler_ptr);
                patches.insert(patches.begin(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                printf("Error doing patch_cmd_handler()! (%s)\n", e.what());
                return -1;
            }
        }
        
        if (flags & FLAG_UNLOCK_NVRAM) {
            try {
                printf("getting get_unlock_nvram_patch() patch\n");
                auto patch = ibpf->get_unlock_nvram_patch();
                patches.insert(patches.begin(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                printf("Error doing get_unlock_nvram_patch()! (%s)\n", e.what());
                return -1;
            }

            try {
                printf("getting get_freshnonce_patch() patch\n");
                auto patch = ibpf->get_freshnonce_patch();
                patches.insert(patches.begin(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                printf("Error doing get_freshnonce_patch()! (%s)\n", e.what());
                return -1;
            }
        }
    }
    
    /* All loaders have the RSA check. */
    try {
        printf("getting get_sigcheck_patch() patch\n");
        auto patch = ibpf->get_sigcheck_patch();
        patches.insert(patches.begin(), patch.begin(), patch.end());
    } catch (tihmstar::exception &e) {
        printf("Error doing patch_rsa_check()! (%s)\n", e.what());
        return -1;
    }
    
    
    for (auto p : patches) {
        printf("applying patch=%p : ",p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        printf("\n");
        uint64_t o = (uint64_t)(p._location - ibpf->find_base());
        memcpy(&iboot_buf[o], p.getPatch(), p.getPatchSize());
    }
    
    /* Write out to the patched file... */
   fp = fopen(output_path, "wb+");
    
    if(!fp) {
        printf("Unable to open file %s!\n", output_path);
        return -1;
    }
    
    printf("Writing out patched file to %s...\n", output_path);
    fwrite(iboot_buf, buf_size, 1, fp);
    fflush(fp);
    fclose(fp);
    free(iboot_buf);
    printf("Quitting...\n");
    
    return 0;
}
