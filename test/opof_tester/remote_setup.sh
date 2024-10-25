Help()
{
   echo "Setup a remote host for OPOF Test Traffic Generation."
   echo "Please perform ssh-copy-id to remote host for best results."
   echo
   echo "Syntax: remote_setup.sh [OPTION]..."
   echo "options:"
   echo "h                 Print this Help."
   echo "r <host>          Install to specified remote host (required)."
   echo "i iface,iface,... Interfaces on which to send traffic"
   echo
   exit
}
while getopts "hr:i:" option; do
   case $option in
      h) Help;;
      r) remote_host=$OPTARG;;
      i) iface=$OPTARG;;
   esac
done

if [[ -z $remote_host ]]; then
    Help;
fi;

echo Copying data...
rsync -r *.py $remote_host:/tmp/opof_test && \
rsync -r *.proto $remote_host:/tmp/opof_test && \

echo Generating grpc service/stub...
ssh root@$remote_host "cd /tmp/opof_test && 
python3 -m grpc_tools.protoc \
    -I. --python_out=. --pyi_out=. --grpc_python_out=. ./opof_tester.proto"

while IFS=',' read -ra IFACE; do
  for i in ${IFACE[@]}; do
    ssh root@$remote_host "ip link set dev $i up"
  done
done <<< $iface
