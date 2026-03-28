# Syscall-Logger for windows : Malware-Grade Strace


# How it works? 
Using Instrumentation callback we get runtime on every sysret, then I unwind the stack(manualy) and using unwind information I can locate the exact function start of each function on the stack, 
then we are saving all the data. 
WE are doing as well logging of every dll load/unload to save guids of each module for post symbol resultion using : LdrRegisterDllNotification.

Then we can run post processing script that downloads all the PDBS and write the exacts symbols.

All the data is retrevied without using any ntdll/kernel32 and done manulay include TID/TIME(TEB/KUSER_SHARED_DATA). 



# Examples:
<img width="2381" height="1300" alt="image" src="https://github.com/user-attachments/assets/9c7f8caf-0da0-4683-a530-d49981f0bc2e" />

<img width="2199" height="795" alt="image" src="https://github.com/user-attachments/assets/fd947305-8f7e-458d-8d1f-21546dca1e11" />

<img width="2089" height="803" alt="image" src="https://github.com/user-attachments/assets/fb495eed-d6cb-42bd-a69f-4f6767ef7a02" />


<img width="2066" height="975" alt="image" src="https://github.com/user-attachments/assets/21b95f9a-8ae2-4842-b4f9-2e62d98ade88" />
