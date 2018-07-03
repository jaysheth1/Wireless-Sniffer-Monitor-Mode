
#!/bin/bash



#./script.sh one two three
#USAGE : sudo ./script channel capture filter


#Positional parameter 1 contains something 00./script.sh 11one 22two




echo "0 $0"
echo "1 $1"
echo "2 $2"
echo "3 $3"
echo "4 $4"
echo "5 $5"







echo -e "USAGE : sudo ./script channel capturefilter outputfilename\n\n"

if [ "$1" != "" ]; then
    echo "Channel : $1.............."
else
    echo "Positional parameter channel is empty, please re-run the script"
    exit 1
fi



if [ "$2" != "" ]; then
    echo "Capture Filter : $2.............."
    filter=$2
else
    echo "Capture Filter parameter is empty............."
    echo "Default Capture Filter: (type data) or (subtype beacon)..............."
    filter="(type data) or (subtype beacon)"
fi


if [ "$3" != "" ]; then
    echo "Capture Filter : $3.............."
    filename=$3
else
    echo "Ouput Filen Name parameter is empty............."
    echo "Default Output File Name: test.pcap..............."
    filename="test.pcap"
fi





pkg="aircrack-ng"
if which $pkg > /dev/null
then
    echo "$pkg installed.............."
else
    echo "$pkg NOT installed.............."
    echo "installing aircrack-ng.............."
    echo -e "\n\n-------------------------------------------------------------------------------------"
    sudo apt-get install aircrack-ng
     echo -e "-------------------------------------------------------------------------------------\n\n"
fi


pkg1="aircrack-ng"
if ldconfig -p | grep libpcap > /dev/null
then
    echo "$pkg installed.............."
else
    echo "$pkg NOT installed.............."
    echo "installing libpcap.............."
    echo -e "\n\n-------------------------------------------------------------------------------------"
    sudo apt-get install libpcap-dev
    echo -e "-------------------------------------------------------------------------------------\n\n"

fi

#ldconfig -p | grep libpcap



wlanname="$(iw dev | awk '$1=="Interface"{print $2}')"
echo "Name of the wireless interface : $wlanname.............."

mon1="mon"

LIST="some sfstring with a substring you want to match"
if echo "$wlanname" | grep -q "$mon1"; then
  echo "Wireless interface is already in the monitor mode, stopping monitor mode..............";
  echo -e "\n\n-------------------------------------------------------------------------------------"
  sudo airmon-ng stop $wlanname
  echo -e "-------------------------------------------------------------------------------------\n\n"
  sleep 10

else
  echo "Wireless interface not in the monitor mode, turning it into monitor mode..............";
fi

wlanname="$(iw dev | awk '$1=="Interface"{print $2}')"
echo "Name of the wireless interface : $wlanname.............."


#ifconfig
mon="mon"
wlanmon="$wlanname$mon"
echo "Enabling monitor mode for interface $wlanmon on channel $1.............."


echo -e "\n\n-------------------------------------------------------------------------------------"
sudo airmon-ng start $wlanname $1
echo -e "-------------------------------------------------------------------------------------\n\n"

wlanname="$(iw dev | awk '$1=="Interface"{print $2}')"



gcc sniffer.c -o sniffer -lpcap
sudo ./sniffer $wlanname -o "$3" -f "$2"

