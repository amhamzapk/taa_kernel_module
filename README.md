# Compilation
### Build without extra debug logs
make
### Build with extra debug logs
make debug
### Clean Build
make clean

# Load & Unload
### Load taa module
sudo insmod taa.ko
### Unload taa module
sudo rmmod taa

# Debug logs
### Clear previous logs
sudo dmesg -C
### Show debug logs
dmesg
### Runtime debug logs
dmesg -w
