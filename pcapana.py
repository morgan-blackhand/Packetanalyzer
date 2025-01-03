import os
from collections import Counter
from scapy.all import rdpcap
import ipaddress
import matplotlib.pyplot as plt

# Function to clear the console screen
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def main():
    # Ask the user for the path to the .pcap file
    file_path = input("Please enter the path to the .pcap file: ")
    
    # Validate the file path
    if not os.path.exists(file_path):
        print("File not found. Please check the path and try again.")
        return

    # Process the .pcap file
    try:
        packets = rdpcap(file_path)  # Read packets from the .pcap file
        flows = Counter()  # Counter to count unique source-destination pairs
        packet_counts = Counter()  # Counter to count packets by source IP
        protocol_counts = Counter()  # Counter to count protocols
        port_counts = Counter()  # Counter to count port usage
        sizes = []  # List to store packet sizes
        times = {}  # Dictionary to track flow timestamps

        for packet in packets:
            if "IP" in packet:
                src = packet["IP"].src  # Source IP
                dst = packet["IP"].dst  # Destination IP
                flows[(src, dst)] += 1  # Count the flow
                packet_counts[src] += 1  # Count packets by source IP
                protocol_counts[packet["IP"].proto] += 1  # Count protocol
                sizes.append(len(packet))  # Track packet size

                # Record timestamps for latency calculations
                flow = (src, dst)
                if flow not in times:
                    times[flow] = []
                times[flow].append(packet.time)

            if "TCP" in packet or "UDP" in packet:
                src_port = packet.sport
                dst_port = packet.dport
                port_counts[src_port] += 1
                port_counts[dst_port] += 1

        # User chooses the type of analysis
        while True:
            clear_screen()  # Clear the screen before displaying the menu
            print("\nChoose an analysis option:")
            print("1. Packet Flows (organized by IP or packets sent)")
            print("2. Protocol Distribution")
            print("3. Packet Size Analysis")
            print("4. Top Talkers (IPs with most packets sent)")
            print("5. Port Usage")
            print("6. Traffic by Subnet")
            print("7. Detect Anomalies")
            print("8. Latency Analysis")
            print("9. Visualize Traffic (e.g., Protocol distribution)")
            print("0. Exit")

            choice = input("Enter your choice: ")

            if choice == "1":
                # Organize flows by IP or packets
                clear_screen()
                print("\nHow would you like to organize the results?")
                print("1. By IP address")
                print("2. By packets sent (descending)")
                sub_choice = input("Enter 1 or 2: ")
                if sub_choice == "1":
                    print("\nOrganized by IP address:")
                    for src in sorted(packet_counts.keys()):  # Sort by IP
                        print(f"\n{src} sent packets to:")
                        for (s, d), count in flows.items():
                            if s == src:
                                print(f"  -> {d}: {count} packets")
                elif sub_choice == "2":
                    print("\nOrganized by packets sent (descending):")
                    for src, count in packet_counts.most_common():
                        print(f"\n{src} sent {count} total packets to:")
                        for (s, d), flow_count in flows.items():
                            if s == src:
                                print(f"  -> {d}: {flow_count} packets")
                input("\nPress Enter to return to the menu...")

            elif choice == "2":
                # Protocol Distribution
                clear_screen()
                print("\nProtocol Distribution:")
                for proto, count in protocol_counts.items():
                    print(f"Protocol {proto}: {count} packets")
                input("\nPress Enter to return to the menu...")

            elif choice == "3":
                # Packet Size Analysis
                clear_screen()
                # Find the largest packet and its flow
                largest_packet = max(packets, key=lambda p: len(p))
                largest_packet_size = len(largest_packet)
                if "IP" in largest_packet:
                    largest_src = largest_packet["IP"].src
                    largest_dst = largest_packet["IP"].dst
                    print(f"\nLargest packet: {largest_packet_size} bytes")
                    print(f"From {largest_src} to {largest_dst}")
                else:
                    print(f"\nLargest packet: {largest_packet_size} bytes (No IP information available)")

                print(f"Smallest packet: {min(sizes)} bytes")
                print(f"Average packet size: {sum(sizes) / len(sizes):.2f} bytes")
                input("\nPress Enter to return to the menu...")

            elif choice == "4":
                # Top Talkers
                clear_screen()
                print("\nTop Talkers (IPs sending the most packets):")
                for ip, count in packet_counts.most_common(5):
                    print(f"{ip}: {count} packets")
                input("\nPress Enter to return to the menu...")

            elif choice == "5":
                # Port Usage
                clear_screen()
                print("\nPort Usage:")
                for port, count in port_counts.most_common(10):
                    print(f"Port {port}: {count} packets")
                input("\nPress Enter to return to the menu...")

            elif choice == "6":
                # Traffic by Subnet
                clear_screen()
                print("\nTraffic by Subnet:")
                subnet_traffic = Counter()
                for src, dst in flows.keys():
                    src_subnet = ipaddress.ip_network(f"{src}/24", strict=False)
                    dst_subnet = ipaddress.ip_network(f"{dst}/24", strict=False)
                    subnet_traffic[(src_subnet, dst_subnet)] += flows[(src, dst)]
                for (src_subnet, dst_subnet), count in subnet_traffic.items():
                    print(f"{src_subnet} -> {dst_subnet}: {count} packets")
                input("\nPress Enter to return to the menu...")

            elif choice == "7":
                # Detect Anomalies
                clear_screen()
                print("\nPotential Anomalies (high traffic):")
                threshold = 1000
                for src, count in packet_counts.items():
                    if count > threshold:
                        print(f"{src} sent an unusually high number of packets: {count}")
                input("\nPress Enter to return to the menu...")

            elif choice == "8":
                # Latency Analysis
                clear_screen()
                print("\nLatency Analysis:")
                for flow, t in times.items():
                    latency = max(t) - min(t)
                    print(f"Flow {flow}: {latency:.2f} seconds")
                input("\nPress Enter to return to the menu...")

            elif choice == "9":
                # Protocol Visualization
                clear_screen()
                protocol_mapping = {6: "TCP", 17: "UDP", 2: "IGMP"}  # Map protocol numbers to names
                protocol_labels = [
                    f"{protocol_mapping.get(proto, f'Unknown({proto})')} ({count} packets)"
                    for proto, count in protocol_counts.items()
                ]
                counts = [count for proto, count in protocol_counts.items()]

                plt.pie(counts, labels=protocol_labels, autopct="%1.1f%%")
                plt.title("Protocol Distribution")
                plt.show()
                input("\nPress Enter to return to the menu...")

            elif choice == "0":
                print("Exiting...")
                break

            else:
                print("Invalid choice. Please try again.")
                input("\nPress Enter to return to the menu...")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
