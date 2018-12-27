/*
 * Copyright 2016-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The above license is because of the function create_absolute_jump that
 * was copied from: https://github.com/pmem/syscall_intercept/src/patcher.c
 */

#include <unistd.h>
#include <fcntl.h>
#include <capstone/capstone.h>

#define REL_JMP_LEN  5
#define ABS_JMP_LEN  14
#define MAX_INS_SIZE 15
#define FAILE        -1


typedef void *(*func_ptr)();

func_ptr patch_func(func_ptr old_func, func_ptr new_func);
int32_t is_capable_of_patching(int fd, func_ptr func, cs_insn **insn);
int32_t is_insn_reloactable(cs_insn insn);
unsigned char *create_absolute_jump(unsigned char *from, void *to);
void space(void);


/*
 *  Hook every function in a process by its address.
 *  Return 'like the origin' function for later use.
 */
func_ptr patch_func(func_ptr old_func, func_ptr new_func)
{
    // Capstone-needed variables.
    cs_insn *insn;
    size_t count;

    // For open /proc/pid/mem.
    int fd;

    // Size of instructions that will be replaced.
    int total_size;

    // Absoloute jmp instruction buffer.
    char jmp[15];

    // For itarate..
    int j;


    fd = open("/proc/self/mem", O_RDWR);
    if (fd == -1){
        printf("Could not open /proc/self/mem\n");
        return (func_ptr)FAILE;
    }

    // Check if it will not break the function to patch it.
    count = is_capable_of_patching(fd, old_func, &insn);
    if (count <= 0){
        printf("function isn't patchable!\n");
        close(fd);
        return (func_ptr)FAILE;
    }

    // Praper to copy the (will be) overriden instuctions
    if (!lseek(fd, (off_t )space, SEEK_SET)){
        close(fd);
        return (func_ptr)FAILE;
    }

    // Copy the (will be) overriden instructions
    // to safe place and save their size.
    total_size = 0;
    for (j = 0; j < count; j++){
        write(fd, insn[j].bytes, insn[j].size);
        total_size += insn[j].size;
    }
    cs_free(insn, count);

    // Add jump back to the original function at the after the copied instructions 
    create_absolute_jump((unsigned char *)jmp, (void *)(old_func + total_size));
    write(fd, jmp, ABS_JMP_LEN);

    // Override the real instructions at the start
    // of theorigin function with jump to our function.
    create_absolute_jump((unsigned char *)jmp, (void *)new_func);
     if (!lseek(fd, (off_t)old_func, SEEK_SET)){
        close(fd);
        return (func_ptr)FAILE;
    }
    write(fd, jmp, ABS_JMP_LEN);

    // Exit.
    close(fd);

    return (func_ptr)space;
}


/*
 *  Check if a function will not be broken after call to hook_function.
 *  On success, return length of the cpastone instructions array of the
 *  needed to be copy instructions at the start of the target function,
 *  the array itself will be available in the (cs_insn **) pointer passed
 *  by the caller. In that case, the free of the array is the caller responsibility.
 *  On faile, on the other side, return -1, and no array will pointed.
 */
int32_t is_capable_of_patching(int fd, func_ptr func, cs_insn **insn){

    // Capstone handler.
    csh handle;

    // Code buffer.
    char code[ABS_JMP_LEN + MAX_INS_SIZE];

    // Number of instruction disassembled by
    // capstone and total-size-in-bytes counter.
    size_t count, total_insn_size = 0;

    // Return value;
    int32_t status = 0;

    // Go to function offset inside /proc/pid/mem
    if (!lseek(fd, (off_t)func, SEEK_SET))
        return FAILE;
    
    if (!read(fd, code, (ABS_JMP_LEN + MAX_INS_SIZE)))
        return FAILE;
    
    // Disaseemble
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return FAILE;
    
    count = cs_disasm(handle, code, (ABS_JMP_LEN + MAX_INS_SIZE), 0, 0, insn);
    if (!count)
        return FAILE;
    
    // Check if there is enough space to insert JMP
    // instruction without override place-relative instructions.
    for (status = 0; status < count; status++){
        if (!is_insn_reloactable((*insn)[status])){
            cs_free(*insn, count);
            status = 0;
            break;
        }

        total_insn_size += (*insn)[status].size;
        if (total_insn_size >= ABS_JMP_LEN){
            status++;
            if (status < count){
                // Free what the caller will not need
                cs_free((*insn), count);
                cs_disasm(handle, code,  total_insn_size, 0, 0, insn);
            }
            break;
        }
    }

    return status;
}


/*
 *  Check if an instruction is place-depended or not.
 */
int32_t is_insn_reloactable(cs_insn insn){
    
    csh handle;

    return (!(cs_reg_read(handle, &insn, X86_REG_IP) ||
            cs_reg_read(handle, &insn, X86_REG_RIP)  ||
            insn.id == X86_INS_SYSCALL ||
            insn.id == X86_INS_CALL    ||
            insn.id == X86_INS_RET     ||
            insn.id == X86_INS_JAE     ||
            insn.id == X86_INS_JA      ||
            insn.id == X86_INS_JBE     ||
            insn.id == X86_INS_JB      ||
            insn.id == X86_INS_JCXZ    ||
            insn.id == X86_INS_JECXZ   ||
            insn.id == X86_INS_JE      ||
            insn.id == X86_INS_JGE     ||
            insn.id == X86_INS_JG      ||
            insn.id == X86_INS_JLE     ||
            insn.id == X86_INS_JL      ||
            insn.id == X86_INS_JMP     ||
            insn.id == X86_INS_JNE     ||
            insn.id == X86_INS_JNO     ||
            insn.id == X86_INS_JNP     ||
            insn.id == X86_INS_JNS     ||
            insn.id == X86_INS_JO      ||
            insn.id == X86_INS_JP      ||
            insn.id == X86_INS_JRCXZ   ||
            insn.id == X86_INS_JS      ||
            insn.id == X86_INS_LOOP    ||
            insn.id == X86_INS_CALL
            ));
}

/*
 * TOOK FROM SYSCALL_INTERCEPT
 * create_absolute_jump(from, to)
 * Create an indirect jump, with the pointer right next to the instruction.
 *
 * jmp *0(%rip)
 *
 * This uses up 6 bytes for the jump instruction, and another 8 bytes
 * for the pointer right after the instruction.
 */
unsigned char *create_absolute_jump(unsigned char *from, void *to)
{
    unsigned char *d = (unsigned char *)&to;

	*from++ = 0xff; /* opcode of RIP based indirect jump */
	*from++ = 0x25; /* opcode of RIP based indirect jump */
	*from++ = 0; /* 32 bit zero offset */
	*from++ = 0; /* this means zero relative to the value */
	*from++ = 0; /* of RIP, which during the execution of the jump */
	*from++ = 0; /* points to right after the jump instruction */


	*from++ = d[0]; /* so, this is where (RIP + 0) points to, */
	*from++ = d[1]; /* jump reads the destination address */
	*from++ = d[2]; /* from here */
	*from++ = d[3];
	*from++ = d[4];
	*from++ = d[5];
	*from++ = d[6];
	*from++ = d[7];

	return from;
}


/*
 *  Just a place to insert the copied
 *  and overrided instructions of a function.
 */
void space(void){
    int stam;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
    stam = 8;
}