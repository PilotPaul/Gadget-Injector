# Gadget-Injector
A small gadget for handy debugging
# What you can do with this gadget?
1. Export or output symbols table of target process
2. Print out the calling backtrace of a function
3. Substitute a function with another one for running process
4. Dump the value of the memory block you wanna see
5. Change the execute pointer (rip/pc) to some where you want
6. Inject or push dynamic shared libraries into the running process
9. Test a function in running process
# Requirement
X86-64 Linux machine is needed
# Documents
1. README.md: as you see right now
2. build.sh: an automatic building shell script
3. test.sh: some test cases
# Thanks
|1|[vikasnkumar](https://github.com/vikasnkumar/hotpatch), my initial source ideology from this gadget
# How to build this tool?
+ Clone this repository or just download archive, then
+ Prepare a X86_64 Linux machine
+ Copy archive to the machine
+ Unzip it, if you get the \*.zip package, then
```bash
  unzip Gadget-Injector-1.0.zip
```
+ Change directory to workspace
```bash
  cd Gadget-Injector-1.0
```
+ Building
```bash
  sh build.sh
```
+ Play it! Use helps manual, then you can see all usages:
```bash
  #injector -h
  Brief of Injector showed followings: [ADDR must start with 0x or 0X, LEN must be a decimal]
  Usage: inject [OPTIONS] PID
  OPTIONS:
   -v[vvvv]                        enable verbose debug information, push it ahead of other options to get all details
   -h                              usage man of this gadget
   -O[FILE]                        export all symbols you can use in this process
   -f ADDR/FUNC-NAME               output functions called backtrace
   -s "FUNC-NAME1 FUNC-NAME2"      stub function1 with function2
   -m "ADDR LEN"                   output the memory content of space which starts from ADDR and lenght is LEN
   -p ADDR/FUNC-NAME               set pc/rip to ADDR or a start address of a function
   -i SOLIB                        insert a shared object(*.so) into this process
   -t ADDR/FUNC-NAME               test a function
   -V                              version of this gadget
```
