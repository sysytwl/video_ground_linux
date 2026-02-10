# 1. Create build directory
cd build

# 2. Configure the project
cmake .. -DCMAKE_BUILD_TYPE=Release
# or for debug
#cmake .. -DCMAKE_BUILD_TYPE=Debug

# 3. Build the project
make

# 4. Run the executable
#sudo ./pcap_inject mon0
