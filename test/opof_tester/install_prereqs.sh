source test_conf.sh

echo Installing local prerequisites...
apt install -qy python3-pip
pip3 install -q grpcio grpcio-tools scapy pytest --upgrade

# Note installation via apt-get doesn't seem to support --pyi_out. Use pip instead.
echo Installing DPU Host prerequisites...
ssh -t root@$DPU_HOST "apt install -qy python3-pip"
ssh -t root@$DPU_HOST "pip3 install -q grpcio grpcio-tools scapy --upgrade"
echo Installing External Host prerequisites...
ssh -t root@$EXT_HOST "apt install -qy python3-pip"
ssh -t root@$EXT_HOST "pip3 install -q grpcio grpcio-tools scapy --upgrade"
