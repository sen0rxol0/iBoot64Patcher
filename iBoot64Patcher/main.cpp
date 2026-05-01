//
//  main.cpp
//  iBoot64Patcher
//
//  Created by tihmstar on 27.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

// Mods by @sen0rxol0
//
// Add libpatchfinder instead of liboffsetfinder64
// Fix build
// Add and fix get_freshnonce_patch(), thanks to Cryptiiiic's fork
// Add input file reading into a buffer
// Improve file read and write
// 
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <libpatchfinder/patch.hpp>
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
    
    const char *inputPath = argv[1];
    const char *outputPath = argv[2];

    FILE *fp = nullptr;

    /* Read decrypted input file into buffer... */
    fp = fopen(inputPath, "rb+");
    
    if (!fp) {
        printf("Unable to open %s!\n", inputPath);
        return -1;
    }

    struct stat st{0};
    
    if (stat(inputPath, &st) < 0) {
        printf("Error getting size for %s!\n", inputPath);
        return -1;
    }

    size_t ibootBufSize = st.st_size;
    char *ibootBuf = (char *) malloc(ibootBufSize);
    
    if (!ibootBuf) {
        printf("Out of memory while allocating region for %s!\n", inputPath);
        fclose(fp);
        return -1;
    }

    fread(ibootBuf, 1, ibootBufSize, fp);
    fclose(fp);

    ibootpatchfinder64 *ibpf = NULL;
    std::vector<patch> patches;

    printf("%s: Starting iBoot64Patch!\n", __FUNCTION__);
    try {
        ibpf = ibootpatchfinder64::make_ibootpatchfinder64(ibootBuf, ibootBufSize);
    } catch (...) {
        printf("Failed initing ibootpatchfinder64!\n");
        return -1;
    }
    printf("Inited ibootpatchfinder64!\n");

    /* All loaders have the RSA check. */
    try {
        auto patch = ibpf->get_sigcheck_patch();
        patches.insert(patches.begin(), patch.begin(), patch.end());
    } catch (tihmstar::exception &e) {
        printf("Error doing patch_rsa_check()!\n");
        return -1;
    }
    printf("Added sigcheck_patch\n");
    
    /* Check to see if the loader has a kernel load routine before trying to apply custom boot args + debug-enabled override. */
    if(ibpf->has_kernel_load()) {
        /* Only bootloaders with the kernel load routines pass the DeviceTree. */
        try {
            auto patch = ibpf->get_debug_enabled_patch();
            patches.insert(patches.begin(), patch.begin(), patch.end());
        } catch (...) {
            printf("Error doing patch_debug_enabled()!\n");
            return -1;
        }
        printf("Added debug_enabled_patch\n");

        if(custom_boot_args) {
            try {
                auto patch = ibpf->get_boot_arg_patch(custom_boot_args);
                patches.insert(patches.begin(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                printf("Error doing patch_boot_args()!\n");
                return -1;
            }
            printf("Added boot_arg_patch(%s)\n", custom_boot_args);
        }
    }
    
    /* Ensure that the loader has a shell. */
    if(ibpf->has_recovery_console()) {
        if (cmd_handler_str && cmd_handler_ptr) {
            try {
                auto patch = ibpf->get_cmd_handler_patch(cmd_handler_str, cmd_handler_ptr);
                patches.insert(patches.begin(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                printf("Error doing patch_cmd_handler()!\n");
                return -1;
            }
            printf("Added cmd_handler_patch(%s,0x%016llx)\n", cmd_handler_str,cmd_handler_ptr);
        }
        
        if (flags & FLAG_UNLOCK_NVRAM) {
            try {
                auto patch = ibpf->get_unlock_nvram_patch();
                patches.insert(patches.begin(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                printf("Error doing get_unlock_nvram_patch()!\n");
                return -1;
            }
            printf("Added unlock_nvram_patch\n");

            try {
                auto patch = ibpf->get_freshnonce_patch();
                patches.insert(patches.begin(), patch.begin(), patch.end());
            } catch (tihmstar::exception &e) {
                printf("Error doing get_freshnonce_patch()!\n");
                return -1;
            }
            printf("Added freshnonce_patch\n");
        }
    }
    
    for (auto p : patches) {
        uint64_t off = (uint64_t)(p._location - ibpf->find_base());
        printf("%s: Applying patch=%p : ",__FUNCTION__,(void*)p._location);
        for (int i=0; i<p._patchSize; i++) {
            printf("%02x",((uint8_t*)p._patch)[i]);
        }
        printf("\n");
        memcpy(&ibootBuf[off], p._patch, p._patchSize);
        //memcpy(&iboot_buf[off], p.getPatch(), p.getPatchSize());
    }
    
    /* Write out to the patched file... */
   fp = fopen(outputPath, "wb+");
    
    if(!fp) {
        printf("Unable to open file %s!\n", outputPath);
        return -1;
    }
    
    printf("Writing out patched file to %s...\n", outputPath);
    fwrite(ibootBuf, ibootBufSize, 1, fp);
    fflush(fp);
    fclose(fp);
    free(ibootBuf);
    printf("Quitting...\n");
    
    return 0;
}
