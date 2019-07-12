#ifdef __linux__
    #if defined(__i386__)
        #include "make_i386_sysv_elf_gas.S"
        #include "jump_i386_sysv_elf_gas.S"
    #elif defined(__x86_64__)
        #include "make_x86_64_sysv_elf_gas.S"
        #include "jump_x86_64_sysv_elf_gas.S"
    #elif defined(__ppc__)
        #include "make_ppc32_sysv_elf_gas.S"
        #include "jump_ppc32_sysv_elf_gas.S"
    #elif defined(__ppc64__)
        #include "make_ppc64_sysv_elf_gas.S"
        #include "jump_ppc64_sysv_elf_gas.S"
    #elif defined(__arm__)
        #include "make_arm_aapcs_elf_gas.S"
        #include "jump_arm_aapcs_elf_gas.S"
    #elif defined(__arm64__)
        #include "make_arm64_aapcs_elf_gas.S"
        #include "jump_arm64_aapcs_elf_gas.S"
    #else
        #error "No arch's"
    #endif
#elif defined(__MACH__)
    #include "make_combined_sysv_macho_gas.S"
    #include "jump_combined_sysv_macho_gas.S"
#else
    #error "not supports"
#endif