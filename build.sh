g++ -o mmake mmake.cpp

./mmake dram
./mmake linuxvmm
./mmake inject08
./mmake vmxmsrs

sudo mknod /dev/vmm c 88 0
sudo mknod /dev/dram c 85 0
sudo chmod a+rw /dev/vmm /dev/dram

g++ -o fileview fileview.cpp
g++ -o tryoutpc tryoutpc.cpp
g++ -o seeevent seeevent.cpp

echo "done"
