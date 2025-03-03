import pyshark as ps
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

"""
        how to get all fields in the transport layer for a protocol

        field_names = packet['[Transport Layer Protocol HERE]']._all_fields
        field_values = packet['[Transport Layer Protocol HERE]']._all_fields.values()

        for field_name, field_value in zip(field_names, field_values):
            print(f"{field_name}: {field_value}")

"""

colors = ['blue', 'red', 'green', 'orange', 'purple'] # colors for graphs

def create_special_df(cap: ps.FileCapture) -> pd.DataFrame:
    """
    Creates a df with the following columns:
    1. packet size
    2. timestamp
    3 .a hashed 4 tuple of the following fields:
        src_ip
        dst_ip
        src_port
        dst_port
    This Df will simulate what the potential attacker knows about the traffic
    :param cap:
    :return: the df
    """
    packet_data = []
    count_packets = 0

    for packet in cap:
        if count_packets % 100 == 0:
            print(f"{count_packets} packets processed")

        # the relevant packet information will be saved in the dict
        packet_info = {}
        try:
            # getting the timestamp
            packet_info['timestamp'] = packet.sniff_timestamp
            # getting the size of the packet
            packet_info['packet_length'] = packet.length

            # getting the rest of the required information
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # the packet's src port and dst port are in its transport layer
            protocol = packet.transport_layer
            src_port = packet[protocol].srcport
            dst_port = packet[protocol].dstport

            # creating the 4-tuple
            info = (src_ip, dst_ip, src_port, dst_port)
            packet_info['four_tuple'] = str(hash(info))

            # adds packet_info to list
            packet_data.append(packet_info)
            count_packets += 1
        except AttributeError:
            pass # skips problematic packets

    df = pd.DataFrame(packet_data)
    return df


def create_df(cap: ps.FileCapture) -> pd.DataFrame:
    """
    creates a df from the provided cap file
    :param cap:
    :return: returns the df
    """
    packet_data = []
    count_packets = 0

    for packet in cap:
        if count_packets % 100 == 0:
            print(f"{count_packets} packets processed")
        # the relevant packet information will be saved in the dict
        packet_info = {}
        try:
            packet_info['timestamp'] = packet.sniff_timestamp # we need the timestamp for easily creating graphs based on dt
            packet_info['packet_length'] = packet.length # we need the size of the entire packet

            # we will first require information from the ip layer
            packet_info['ip_src'] = packet.ip.src
            packet_info['ip_dst'] = packet.ip.dst
            packet_info['ip_version'] = packet.ip.version
            packet_info['ip_proto'] = packet.ip.proto
            packet_info['ip_ttl'] = packet.ip.ttl

            protocol = packet.transport_layer # getting the protocol used for the transport layer

            # getting general transport layer values from either the tcp or udp protocols
            packet_info['protocol'] = protocol
            packet_info['src_port'] = packet[protocol].srcport
            packet_info['dst_port'] = packet[protocol].dstport

            # getting tcp specific values
            if protocol == 'TCP':
                packet_info['tcp_payload_size'] = packet.tcp.len
                packet_info['tcp_seq'] = packet.tcp.seq
                packet_info['tcp_ack_flag'] = packet.tcp.ack
                packet_info['tcp_window_size'] = packet.tcp.window_size

            # getting udp specific values
            if protocol == 'UDP':
                packet_info['udp_length'] = packet.udp.length

            # getting quic specific values
            if 'QUIC' in str(packet.layers):
                packet_info['protocol'] = 'QUIC'
                packet_info['quic_length'] = packet.quic.packet_length
                try:
                    packet_info['quic_pkt_number'] = packet.quic.packet_number
                    packet_info['quic_frame'] = packet.quic.frame
                    packet_info['quic_header_encrypted'] = False
                except AttributeError as e:
                    # on encrypted quic packets these values are not available
                    packet_info['quic_pkt_number'] = None
                    packet_info['quic_frame'] = None
                    packet_info['quic_header_encrypted'] = True

            # getting tls specific values
            if 'TLS' in str(packet.layers):
                # since there is no easily accessible method (in the documentation that I found, and research I conducted)
                # to gain access to the specific variables we want to get, we will manually take them out of the variables
                # that are available

                try:
                    tls_records = str(packet.tls.record).split(' ')

                    # getting the exact tls version
                    packet_info['protocol'] = tls_records[0]

                    # tls can have multiple things in the record layer,
                    # a handshake (CH or SH), an APD such as HTTP, and CCSP to change the cipher spec

                    # getting handshake protocol
                    if tls_records.__contains__('Handshake Protocol:'):
                        index = tls_records.index('Handshake Protocol:')
                        packet_info['tls_handshake_protocol'] = tls_records[index + 1]
                        packet_info['tls_header_encrypted'] = False
                    else:
                        # if there is no handshake the tls is encrypted
                        packet_info['tls_header_encrypted'] = True
                    # getting change cipher spec protocol
                    if tls_records.__contains__('Change Cipher Spec Protocol:'):
                        index = tls_records.index('Change Cipher Spec Protocol:') # getting the index
                        packet_info['tls_change_cipher_spec'] = tls_records[index + 1]
                    # getting application data protocol
                    if tls_records.__contains__('Application Data Protocol:'):
                        index = tls_records.index('Application Data Protocol:') # getting the index
                        packet_info['tls_application_data'] = tls_records[index + 1]

                except AttributeError as e:
                    pass

            # adds listing to list
            packet_data.append(packet_info)
            count_packets += 1
        except AttributeError:
            pass # on error skips problematic packet

    # converting all files into a dataframe
    df = pd.DataFrame(packet_data)
    return df

def save_to_csv(df: pd.DataFrame, df_name: str):
    """
    saves the df as a csv file based on the provided name
    :param df:
    :param df_name:
    :return:
    """
    df.to_csv(f"WiresharkRecordingSpecialCSV/{df_name}.csv")

def create_csv_from_pcapngs():
    """
    Gets the pcap files for each of the 5 recordings
    and turns each of them to a csv file based on the specified parameters decided upon
    for further processing and pattern identification
    :return:
    """
    # getting the pcap files
    chrome_pcap = ps.FileCapture("WiresharkRecordings/ChromeRecordingFiltered.pcapng")
    firefox_pcap = ps.FileCapture("WiresharkRecordings/FirefoxRecordingFiltered.pcapng")
    spotify_pcap = ps.FileCapture("WiresharkRecordings/SpotifyRecordingFiltered.pcapng")
    youtube_pcap = ps.FileCapture("WiresharkRecordings/YoutubeRecordingFiltered.pcapng")
    zoom_pcap = ps.FileCapture("WiresharkRecordings/ZoomRecordingFiltered.pcapng")

    # creating the dataframes and saving the csv files
    print("Creating Chrome df and saving it...")
    chrome_df = create_df(chrome_pcap)
    save_to_csv(chrome_df, "chrome")
    print("Creating Firefox df and saving it...")
    firefox_df = create_df(firefox_pcap)
    save_to_csv(firefox_df, "firefox")
    print("Creating Spotify df and saving it...")
    spotify_df = create_df(spotify_pcap)
    save_to_csv(spotify_df, "spotify")
    print("Creating Youtube df and saving it...")
    youtube_df = create_df(youtube_pcap)
    save_to_csv(youtube_df, "youtube")
    print("Creating Zoom df and saving it...")
    zoom_df = create_df(zoom_pcap)
    save_to_csv(zoom_df, "zoom")

    # getting the recording for Question 4 set up:
    print("Creating Q4 Recording and saving it...")
    q4_pcap = ps.FileCapture("WiresharkRecordings/Q4Traffic.pcapng")
    # creating the special dataframe
    q4_df = create_special_df(q4_pcap)
    save_to_csv(q4_df, "q4")

    # getting the recording for the Bonus Question set up:
    print("Creating Bonus Question Recording and saving it...")
    bq_pcap = ps.FileCapture("WiresharkRecordings/BonusTraffic.pcapng")
    # creating the special dataframe
    bq_df = create_special_df(bq_pcap)
    save_to_csv(bq_df, "bq")


def packet_number_over_time(dfs:list[pd.DataFrame], df_names: list[str]):
    """
    creates an area gaining graph for amounts of packets over time for each data frame
    :return:
    """
    # create fig with 5 subplots
    fig, axes = plt.subplots(1, 5, figsize=(20,4), sharey=True)

    for i, df in enumerate(dfs):
        df['entry_count'] = range(1, len(df) + 1) # cumulative count
        axes[i].fill_between(df['timestamp'], df['entry_count'], color=colors[i], alpha=0.3)
        axes[i].plot(df['timestamp'], df['entry_count'], color=colors[i])
        axes[i].set_title(f"Amount of Packets over time [{df_names[i]}]")
        axes[i].set_xlabel("time [s]")

    axes[0].set_ylabel("amount of packets [N]")
    plt.tight_layout()
    plt.show()

def ttl_distribution(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    Creates a graph showing the ttl distribution of packets in each df
    :param dfs:
    :param df_names:
    :return:
    """
    fig, ax = plt.subplots(figsize=(20,4))
    for i, df in enumerate(dfs):
        sns.kdeplot(df['ip_ttl'], color=colors[i], label=df_names[i] ,ax=ax)

    ax.set_xlabel("TTL Values")
    ax.set_ylabel("Density")
    ax.set_title("TTL Value Distribution")
    ax.legend()
    plt.show()

def window_size_over_time(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    Creates a graph for each df showing the window size of their tcp packets over time
    :param dfs:
    :param df_names:
    :return:
    """
    fig, axes = plt.subplots(1, 5, figsize=(40,6), sharey=True)

    for i, df in enumerate(dfs):
        # filter to only have packets with window sizes
        df_tcp = df.dropna(subset=['tcp_window_size'])
        axes[i].plot(df_tcp['timestamp'], df_tcp['tcp_window_size'], color=colors[i])
        axes[i].set_xlabel("Time [s]")
        axes[i].set_title(f"Window Size over Time {df_names[i]}")

    axes[0].set_ylabel("Window Size")
    plt.show()

def quic_packet_length_distribution(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    Creates a graph showing the quic packet length distribution of each df
    :param dfs:
    :param df_names:
    :return:
    """
    fig, ax = plt.subplots(figsize=(8,5))
    for i, df in enumerate(dfs):
        if 'quic_length' in df.columns:
            # removes non-quic packets and plots them
            sns.kdeplot(df['quic_length'].dropna(), color=colors[i], label=df_names[i], ax=ax, alpha=0.6)

    ax.set_xlabel("QUIC Packet Length")
    ax.set_ylabel("Density")
    ax.set_title("QUIC Packet Length Distribution")
    ax.legend()
    plt.show()

def packet_length_distribution(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    Creates a graph showing the packet length distribution of each df
    :param dfs:
    :param df_names:
    :return:
    """
    fig, ax = plt.subplots(figsize=(8,5))
    for i, df in enumerate(dfs):
        # using the log function on the data to remove the tail
        sns.kdeplot(np.log1p(df['packet_length']), color=colors[i], label=df_names[i], ax=ax, alpha=0.6)

    ax.set_xlabel("ln(Packet Length+1)")
    ax.set_ylabel("Density")
    ax.set_title("Packet Size Distribution")
    ax.legend()
    plt.show()

def tcp_to_udp_comparison(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    Creates a graph for each df comparing the frequency and size of the udp and tcp packets
    they are using
    :param dfs:
    :param df_names:
    :return:
    """
    fig, axes = plt.subplots(1, 5, figsize=(30,5))
    for i, df in enumerate(dfs):
        tcp_df = df.dropna(subset=['tcp_window_size']) # only tcp packets will have this value
        sns.histplot(np.log1p(tcp_df["packet_length"]), bins=30, color='blue', ax=axes[i], label='UDP', stat='density')
        udp_df = df.dropna(subset=['udp_length']) # only udp packets will have this value
        sns.histplot(np.log1p(udp_df['packet_length']), bins=30, color='red', ax=axes[i], label='TCP', stat='density')
        axes[i].set_xlabel("ln(packet length+1)") # to create better scaling
        axes[i].set_title(f"Comparison of TCP vs UDP Packet Length in {df_names[i]}")
        axes[i].legend()

    axes[0].set_ylabel("Density")

    plt.tight_layout()
    plt.show()

def tlp_percentages(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    creates a pie chart for each df based on the usage percentage for each Transport Layer Protocol (TLS)
    used in it
    :param dfs:
    :param df_names:
    :return:
    """
    fig, axes = plt.subplots(5, 1, figsize=(7,20))
    for i,df in enumerate(dfs):
        # counts occurrences for each protocol
        protocol_counts = df['protocol'].value_counts()

        # calculate the percentiles for each protocol
        total_num_packets = protocol_counts.sum()
        percentages = (protocol_counts / total_num_packets) * 100

        # plot pie chart
        axes[i].pie(percentages, labels=None, startangle=90, wedgeprops={'edgecolor':'black'})
        axes[i].set_title(f"Transport Layer Protocols Percentiles: {df_names[i]}")

        legends_labels = [f'{protocol}: {percentage:.1f}%' for protocol, percentage in zip(protocol_counts.index, percentages)]
        axes[i].legend(legends_labels, title="Protocols", loc='center left', bbox_to_anchor=(1, 0.5), edgecolor='black')

    plt.tight_layout()
    plt.show()

def encryption_protocols_percentages(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    creates a pie chart for each df based on how much of the data was sent using
    a transport layer protocol that automatically encrypts the data
    (the percentile usage of TLS protocols and QUIC)
    :param dfs:
    :param df_names:
    :return:
    """
    fig, axes = plt.subplots(5, 1, figsize=(7, 20))
    for i, df in enumerate(dfs):
        # counts occurrences for how many packets use encrypted protocols and how many don't
        encryption_protocols_counts = df['ETP'].value_counts()

        # calculate the percentiles for each protocol
        total_num_packets = encryption_protocols_counts.sum()
        indexes = encryption_protocols_counts.index.map({True: 'Encrypted', False: 'Not Encrypted'})

        percentages = (encryption_protocols_counts / total_num_packets) * 100

        # plot pie chart
        axes[i].pie(percentages, labels=None, startangle=90, wedgeprops={'edgecolor':'black'})
        axes[i].set_title(f"Encrypted Transport Protocols Percentiles: {df_names[i]}")

        legends_labels = [f'{encryption}: {percentage:.1f}%' for encryption, percentage in zip(indexes, percentages)]
        axes[i].legend(legends_labels, title="Encryptions", loc='center left', bbox_to_anchor=(1, 0.5), edgecolor='black')

    plt.tight_layout()
    plt.show()

def filter_low_freq_ip(ip_counts, threshold):
    """
    filters low frequency IPs (IPs that weren't used a lot)
    :param ip_counts:
    :param threshold:
    :return:
    """
    # makes sure the ip count must appear at least threshold times
    return ip_counts[ip_counts >= threshold]

def src_ip_bar_graph(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    a bar graph showing the frequency of each source IP
    :param dfs:
    :param df_names:
    :return:
    """
    ip_counts = []
    threshold = 100 # there are a lot of packets
    # count the occurrences for each source ip in each df
    for df in dfs:
        ip_counts.append(filter_low_freq_ip(df['ip_src'].value_counts(), threshold))

    fig, axes = plt.subplots(1, 5, figsize=(30,6))
    for i, df in enumerate(dfs):
        ip_counts[i].plot(kind='bar', ax=axes[i], color=colors[i])
        axes[i].set_title(f"Source IP Frequency: {df_names[i]}")
        axes[i].set_xlabel("Source IP")
        axes[i].set_ylabel("Count")
        axes[i].tick_params(axis='x', labelrotation=45)

    plt.tight_layout()
    plt.show()

def dst_ip_bar_graph(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    a bar graph showing the frequency of each destination IP
    :param dfs:
    :param df_names:
    :return:
    """
    ip_counts = []
    threshold = 100  # there are a lot of packets
    # count the occurrences for each source ip in each df
    for df in dfs:
        ip_counts.append(filter_low_freq_ip(df['ip_dst'].value_counts(), threshold))

    fig, axes = plt.subplots(1, 5, figsize=(30, 6))
    for i, df in enumerate(dfs):
        ip_counts[i].plot(kind='bar', ax=axes[i], color=colors[i])
        axes[i].set_title(f"Destination IP Frequency: {df_names[i]}")
        axes[i].set_xlabel("Destination IP")
        axes[i].set_ylabel("Count")
        axes[i].tick_params(axis='x', labelrotation=45)

    plt.tight_layout()
    plt.show()

def filter_low_freq_port(port_counts, threshold):
    """
    filters low frequency ports (ports that weren't used a lot)
    :param port_counts:
    :param threshold:
    :return:
    """
    # makes sure the port count must appear at least threshold times
    return port_counts[port_counts >= threshold]

def src_port_bar_graph(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    a bar graph based on the source ports
    :param dfs:
    :param df_names:
    :return:
    """
    ports_counts = []
    threshold = 100
    for df in dfs:
        ports_counts.append(filter_low_freq_port(df['src_port'].value_counts(), threshold))

    fig, axes = plt.subplots(1, 5, figsize=(30,6))
    for i, df in enumerate(dfs):
        ports_counts[i].plot(kind='bar', ax=axes[i], color=colors[i])
        axes[i].set_title(f"Source Port Frequency: {df_names[i]}")
        axes[i].set_xlabel("Source Port")
        axes[i].set_ylabel("Count")
        axes[i].tick_params(axis='x', labelrotation=45)

    plt.tight_layout()
    plt.show()

def dst_port_bar_graph(dfs: list[pd.DataFrame], df_names: list[str]):
    """
    a bar graph based on the destination ports
    :param dfs:
    :param df_names:
    :return:
    """
    ports_counts = []
    threshold = 100
    for df in dfs:
        ports_counts.append(filter_low_freq_port(df['dst_port'].value_counts(), threshold))

    fig, axes = plt.subplots(1, 5, figsize=(30, 6))
    for i, df in enumerate(dfs):
        ports_counts[i].plot(kind='bar', ax=axes[i], color=colors[i])
        axes[i].set_title(f"Destination Port Frequency: {df_names[i]}")
        axes[i].set_xlabel("Destination Port")
        axes[i].set_ylabel("Count")
        axes[i].tick_params(axis='x', labelrotation=45)

    plt.tight_layout()
    plt.show()


def packet_number_over_time_extra(df: pd.DataFrame, df_name: str):
    """
    Graph for q4 or bonus question related to amount of packets over time
    :param df:
    :param df_name:
    :return:
    """
    # create fig
    fig, ax = plt.subplots(figsize=(10, 5))
    df['entry_count'] = range(1, len(df) + 1)  # cumulative count

    ax.fill_between(df['timestamp'], df['entry_count'], color='blue', alpha=0.3)
    ax.plot(df['timestamp'], df['entry_count'], color='blue')
    ax.set_title(f"Amount of Packets over time [{df_name} graph]")
    ax.set_xlabel("time [s]")
    ax.set_ylabel("amount of packets [N]")

    plt.tight_layout()
    plt.show()


def packet_length_distribution_extra(df: pd.DataFrame, df_name: str):
    """
    Graph for q4 or bonus question related to size of packets over time
    :param df:
    :param df_name:
    :return:
    """
    fig, ax = plt.subplots(figsize=(8, 5))
    # using the log function on the data to remove the tail
    sns.kdeplot(np.log1p(df['packet_length']), color='blue', label=f"{df_name} graph", ax=ax, alpha=0.6)

    ax.set_xlabel("ln(Packet Length+1)")
    ax.set_ylabel("Density")
    ax.set_title("Packet Size Distribution")
    ax.legend()
    plt.show()

def filter_low_freq_tuple(tuple_counts, threshold):
    """
    removes low frequency tuples
    :param tuple_counts:
    :param threshold:
    :return:
    """
    # makes sure the tuple count must appear at least threshold times
    return tuple_counts[tuple_counts >= threshold]

def four_tuple_freq_extra(df: pd.DataFrame, df_name: str):
    """
    Graph for q4 or bonus question related to the 4-tuple frequency
    :param df:
    :param df_name:
    :return:
    """
    threshold = 50
    tuple_counts=filter_low_freq_tuple(df['four_tuple'].value_counts(), threshold)

    fig, ax = plt.subplots(figsize=(8, 5))
    tuple_counts.plot(kind='bar', ax=ax, color='blue')
    ax.set_title(f"4-tuple Frequency [{df_name} graph]")
    ax.set_xlabel("4-tuple")
    ax.set_ylabel("Count")
    ax.tick_params(axis='x', labelrotation=45)

    plt.tight_layout()
    plt.show()

def move_timestamp_to_zero(df: pd.DataFrame) -> pd.DataFrame:
    """
    receives a df and moves the timestamp to start from 0
    :param df:
    :return:
    """
    df['timestamp'] = df['timestamp'] - df['timestamp'].iloc[0]
    return df

def encrypted_payload_packets(df:pd.DataFrame) -> pd.DataFrame:
    """
    receives a df and checks for each packet if it has a protocol that encrypts it's payload
    """

    df['ETP'] = df.apply(
        lambda row: False if(
        (row['protocol'] == 'TCP') or
        (row['protocol'] == 'UDP')
        ) else True, axis=1
    )

    return df

def set_up_dfs() -> list[pd.DataFrame]:
    """
    Creates all relevant dataframes
    :return: returns them in a list
    """
    chrome_df = pd.read_csv("WiresharkRecordingSpecialCSV/chrome.csv")
    chrome_df = chrome_df.drop(columns=['Unnamed: 0'], errors="ignore")  # index col is duplicated
    chrome_df = move_timestamp_to_zero(chrome_df)  # moves timestamps to start from 0
    chrome_df = encrypted_payload_packets(chrome_df)  # adds encryption field
    firefox_df = pd.read_csv("WiresharkRecordingSpecialCSV/firefox.csv")
    firefox_df = firefox_df.drop(columns=['Unnamed: 0'], errors="ignore")  # index col is duplicated
    firefox_df = move_timestamp_to_zero(firefox_df)  # moves timestamps to start from 0
    firefox_df = encrypted_payload_packets(firefox_df)  # adds encryption field
    spotify_df = pd.read_csv("WiresharkRecordingSpecialCSV/spotify.csv")
    spotify_df = spotify_df.drop(columns=['Unnamed: 0'], errors="ignore")  # index col is duplicated
    spotify_df = move_timestamp_to_zero(spotify_df)  # moves timestamps to start from 0
    spotify_df = encrypted_payload_packets(spotify_df)  # adds encryption field
    youtube_df = pd.read_csv("WiresharkRecordingSpecialCSV/youtube.csv")
    youtube_df = youtube_df.drop(columns=['Unnamed: 0'], errors="ignore")  # index col is duplicated
    youtube_df = move_timestamp_to_zero(youtube_df)  # moves timestamps to start from 0
    youtube_df = encrypted_payload_packets(youtube_df)  # adds encryption field
    zoom_df = pd.read_csv("WiresharkRecordingSpecialCSV/zoom.csv")
    zoom_df = zoom_df.drop(columns=['Unnamed: 0'], errors="ignore")  # index col is duplicated
    zoom_df = move_timestamp_to_zero(zoom_df)  # moves timestamps to start from 0
    zoom_df = encrypted_payload_packets(zoom_df)  # adds encryption field
    return [chrome_df, firefox_df, spotify_df, youtube_df, zoom_df]

def print_graph_options():
    """
    This function prints what graph options you can choose from
    :return:
    """
    print("The following graphs are available:")
    print("1. Packet Amount over Time")
    print("2. Packet Size Distribution")
    print("3. SRC IP Bar Graph")
    print("4. DST IP Bar Graph")
    print("5. TTL Value Distribution")
    print("6. TCP Window Size over Time")
    print("7. QUIC Packet Length Distribution")
    print("8. SRC PORT Bar Graph")
    print("9. DST PORT Bar Graph")
    print("10. Compare TCP vs UDP")
    print("11. Transport Layer Protocols Percentiles")
    print("12. Encrypted TLP Usage Percentiles")


def run_statistics():
    """
    This function is used for the graph statistics
    :return:
    """
    # gets all the dfs
    dfs = set_up_dfs()
    df_names = ["chrome", "firefox", "spotify", "youtube", "zoom"]

    print_graph_options()
    while True:
        try:
            answer = int(input("which graph would you like to see next? (enter 1-12, 0 to end)"))
            if answer == 0: # quiting
                print("closing statistics")
                return
            elif answer == 1: # Packet Amount over Time
                packet_number_over_time(dfs, df_names)
            elif answer == 2: # Packet Size Distribution
                packet_length_distribution(dfs, df_names)
            elif answer == 3: # SRC IP Bar Graph
                src_ip_bar_graph(dfs, df_names)
            elif answer == 4: # DST IP Bar Graph
                dst_ip_bar_graph(dfs, df_names)
            elif answer == 5: # TTL Value Distribution
                ttl_distribution(dfs, df_names)
            elif answer == 6: # TCP Window Size over Time
                window_size_over_time(dfs, df_names)
            elif answer == 7: # QUIC Packet Length Distribution
                quic_packet_length_distribution(dfs, df_names)
            elif answer == 8: # SRC PORT Bar Graph
                src_port_bar_graph(dfs, df_names)
            elif answer == 9: # DST PORT Bar Graph
                dst_port_bar_graph(dfs, df_names)
            elif answer == 10: # Compare TCP vs UDP
                tcp_to_udp_comparison(dfs, df_names)
            elif answer == 11: # Transport Layer Protocols Percentiles
                tlp_percentages(dfs, df_names)
            elif answer == 12: # Encrypted TLP Usage Percentiles
                encryption_protocols_percentages(dfs, df_names)
            else: # invalid answer
                raise IndexError
        except ValueError:
            print("Please enter a valid number.")
        except IndexError:
            print("Please enter number between 1 and 12 (or 0 to quit).")

def display_extra_options():
    """
    This function is used for the possible graphs related to q4 and the bonus question
    :return:
    """
    print("The following graphs are available:")
    print("1. Packet Amount over Time")
    print("2. Packet Size Distribution")
    print("3. 4-Tuple Frequency")

def run_extra_stats(csv_name: str):
    """
    This function lets you pick between graphs of all 3 fields relevant to question 4 and the bonus question
    :param csv_name: the name of the csv file (without .csv extension)
    :return:
    """
    df = pd.read_csv(f"WiresharkRecordingSpecialCSV/{csv_name}.csv")
    df = df.drop(columns=['Unnamed: 0'], errors="ignore")  # index col is duplicated
    df = move_timestamp_to_zero(df) # moves timestamps to start from 0
    display_extra_options()

    if csv_name == "q4":
        print("displaying for Q4 related Traffic")
    elif csv_name == "bq":
        print("displaying for the Bonus Question's Traffic")
    else:
        raise ValueError("Invalid csv name")

    while True:
        try:
            answer = int(input("which graph would you like to see next? (enter 1-3, 0 to end)"))
            if answer == 0: # quiting
                print(f"closing {csv_name}...")
                return
            if answer == 1:
                packet_number_over_time_extra(df, csv_name)
            elif answer == 2:
                packet_length_distribution_extra(df, csv_name)
            elif answer == 3:
                four_tuple_freq_extra(df, csv_name)
            else: # invalid answer
                raise IndexError
        except ValueError:
            print("Please enter a valid number.")
        except IndexError:
            print("Please enter number between 1 and 3 (or 0 to quit).")


def main():
    print("Hello,")
    print("There are existing csv files with all the information relevant to the graphs,")
    print("But would you like to recreate them using the pcapng files? (y/n) ")
    print("Though it might take a while...")
    answer = input().lower()
    while answer != 'y' and answer != 'n':
        answer = input("please enter 'y' or 'n': ").lower()

    if answer == "y":
        create_csv_from_pcapngs()

    while True:
        print("Press 1 to view graphs related to questions 1-3, press 2 for graphs related to question 4, 3 for bonus question's graphs")
        print("press 0 to quit:")
        answer = str(input())

        # making sure input is correct
        while answer != '0' and answer != '1' and answer != '2' and answer != '3':
            answer = str(input("please enter 1 or 2, or 0 to quit: "))

        # choosing correct option
        if answer == '0':
            print("Closing program...")
            break

        if answer == '1':
            # run graph function chooser
            run_statistics()

        if answer == '2':
            # run functions related to q4
            run_extra_stats("q4")

        if answer == '3':
            # run functions related to the bonus question
            run_extra_stats("bq")



if __name__ == "__main__":
    main()