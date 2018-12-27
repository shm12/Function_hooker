#include <stdio.h>
#include <dlfcn.h>
#include "func_hook.c"

void *(*origin_dlopen)(const char *, int) = dlopen;

void *new_dlopen(const char *filename, int flag){
    ("In our dlopen! Filename: %s\n", filename);
    return origin_dlopen(filename, flag);
}

int main() {
   dlopen("nothing", RTLD_LAZY);
   printf("No hook\n");

   origin_dlopen = patch_func((func_ptr)dlopen, (func_ptr)new_dlopen);
   dlopen("nothing", RTLD_LAZY);
}
