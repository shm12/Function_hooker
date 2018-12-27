# **Function hooker**
Hook (almost) every function by patching it. This can be helpful when the LD_PRELOAD trick would not work, like when you have to hook libld functions (libld is loaded before LD_PRELOAD).


# dlopen hook example
For example, here is hook of dlopen.
First we include func_hook.h:
```C
#include "func_hook.h"
```
Now we define global function pointer for the old dlopen:
```C
void *(*origin_dlopen)(const char *, int) = dlopen;
```
Our new dlopen:
```C
void *new_dlopen(const char *filename, int flag){
    ("In our dlopen! Filename: %s\n", filename);
    return origin_dlopen(filename, flag);
}
```
In our main function we call to dlopen twice, first time before the hook registration, and second time after the hooking, in order to see the difference:
```C
int main() {
   dlopen("nothing", RTLD_LAZY);
   printf("No hook\n");

   origin_dlopen = patch_func((func_ptr)dlopen, (func_ptr)new_dlopen);
   dlopen("nothing", RTLD_LAZY);
}
```
Now, if we run the follows:
```bash
$ gcc dlopen_hook_example.c func_hook.c -ldl -o dlopen_hook
$ ./dlopen_hook
```
The output will be:
```
No hook
In our dlopen! Filename: nothing
```

# How it works
The function patch_func is checking if there is enough space at the start of the 'old' function to insert jump instruction to our 'new' function without to override location depended instructions (such as jump). If there is enough space, the old insructions are copied to 'safe place' and then overrided by jump instruction.
In the 'safe place', jump is written right after the reserved instructions, back to the natural continuation of the original function, and thus, a pointer to the start of the reserved instuction can be treated like pointer to the original function.

# Issues
- Loops. If the old function starts with loop, it can be that there is jump to one of the overriden instructins, and the patch will break the original function without to notice at all.
- And more.

Anyway, such things needs to be done carefully.

# To Do
- Enable multi function hooking (for now, only one function can be hooked at a time).
- Take care of instructions like jump and reloacet them (copy them and fix their far value), instead of mark them as 'not-relocatable's.
- And more.
