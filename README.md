# Packetanalyzer
This tool gives a few options for different data analysis tools for a pcap file.
You may need to install sudo apt install python3-scapy at least in my case.

Steps

1. Download the script and any independcies for example I needed.
   install sudo apt install python3-scapy
2. Specify the path to your file you can go to its directory and type "pwd"
3. Run the script with the pcap


Here are additional steps to download the files if you are using WSL on windows since it's headless

1. wget https://raw.githubusercontent.com/morgan-blackhand/Packetanalyzer/main/pcapana.py
2. wget https://raw.githubusercontent.com/morgan-blackhand/Packetanalyzer/main/sample.pcap
Sample is used as it's bigger but you can use the smaller one with
wget https://github.com/morgan-blackhand/Packetanalyzer/blob/main/ETH_IPv4_TCP_syn.pcap
4. Download scapy with "install sudo apt install python3-scapy"
5. Use "pwd" and "ls" to find the file path and run it.
