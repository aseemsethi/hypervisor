Based on http://www.cs.usfca.edu/~cruse/cs686s07/
Rep cloned from https://github.com/dweinstein/linuxvmm

My computer
[asethi@localhost hypervisor]$ uname -a
Linux localhost.localdomain 3.10.0-693.11.1.el7.x86_64 #1 SMP Mon Dec 4 23:52:40 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

Initial commit to get linuxvmm to compile
- correct VM_RESERVED
- fix create proc entry, since that changed in kernel 3.10

------------------------------------------------------------
g++ -o mmake mmake.cpp

./mmake linuxvmm
./mmake vmxmsrs
./mmake dram


sudo mknod /dev/vmm c 88 0
sudo mknod /dev/dram c 85 0
sudo chmod a+rw /dev/vmm
sudo chmod a+rw /dev/dram


sudo insmod linuxvmm.ko
sudo insmod dram.ko


g++ -o tryoutpc tryoutpc.cpp
g++ -o fileview fileview.cpp


sudo ./tryoutpc
sudo ./fileview /dev/dram


Observe value in EAX [15:0] ...
