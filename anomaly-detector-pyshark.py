#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Feb 13 13:35:54 2021

@author: Rocco Guglielmo
"""
import argparse
from statistics import mean, mode
import pyshark

#HELP
parser = argparse.ArgumentParser(description='IoT encrypted traffic analyzer')
parser.add_argument('-f', '--file', type=str,
                    help='File pcap to analize, default=file-pcapng/traffic-with-operations-thermostat.pcapng',
                    default="file-pcapng/traffic-with-operations-thermostat.pcapng")
args = parser.parse_args()


# DATI
sliding_window = []
window_width = 60
shift = 1
file = args.file
#file = 'file-pcapng/traffic-stanby.pcapng'
#file = 'file-pcapng/spegni-accendi-thermostat.pcapng'
#file = 'file-pcapng/traffic-with-operations-thermostat.pcapng'

IOT_DEVICE_IP = "10.42.0.175"
#KNOW_SERVER [13.81.202.19, 104.45.28.116, 13.95.157.235]


# FUNCTIONS
def fill_list(packets_list):
    count = 0
    riferimento = float(packets[0].sniff_timestamp)
    for packet in packets_list:
        relative_time = float(packet.sniff_timestamp) - riferimento
        #print("Relative time : " + str(relative_time))
        if relative_time < window_width:
            count = count + 1
            sliding_window.append(packet)
            #packets_list.remove(packet)
        else:
            del packets_list[:count]
            #print("There are " + str(len(sliding_window)) + " items in the sliding_window")
            return sliding_window


def update_list(packets_list, sliding_window):
    count = 0
    riferimento = float(sliding_window[0].sniff_timestamp)
    for packet in sliding_window:
        relative_time = float(packet.sniff_timestamp) - riferimento
        if relative_time < shift:
            count = count + 1
            #sliding_window.remove(packet)
        else:
            del sliding_window[:count]
            break
    count = 0
    riferimento = float(sliding_window[0].sniff_timestamp) + window_width
    for packet in packets_list:
        relative_time = float(packet.sniff_timestamp) - riferimento
        if relative_time < 0:
            count = count + 1
            sliding_window.append(packet)
            #packets_list.remove(packet)
        else:
            del packets_list[:count]
            return packets_list, sliding_window


def media_downstream(sliding_window):
    count = 0
    size_list = []
    throughput = 0
    media = 0
    for packet in sliding_window:
        try:
            #print("count : " + str(count) + " IP_DST : " + packet.ip.dst + " Protocol : " + packet.highest_layer + " Packet length: " + str(packet.length))
            if packet.ip.dst == IOT_DEVICE_IP:
                if packet.highest_layer == "SSL":
                    size_list.append(float(packet.length))
        except AttributeError:
            pass
            #print("Continua...")
    count = len(size_list)
    if count == 0:
        media = -1
        throughput = -1
    else:
        media = mean(size_list)
        throughput = sum(size_list)

    print("Downstream SIZE LIST: " + str(size_list) + " AVERAGE : " + str(media) + " COUNT : " + str(count) + " THROUGHPUT : " + str(throughput))
    return media, count, throughput


def moda_upstream(sliding_window):
    count = 0
    size_list = []
    moda = 0
    for packet in sliding_window:
        try:
            #print("count : " + str(count) + " IP_DST : " + packet.ip.dst + " Protocol : " + packet.highest_layer + " Packet length: " + str(packet.length))
            if packet.ip.src == IOT_DEVICE_IP:
                if packet.highest_layer == "SSL":
                    size_list.append(int(packet.length))
        except AttributeError:
            pass
            #print("Continua...")
    count = len(size_list)
    if count == 0:
        throughput = -1
    else:
        throughput = sum(size_list)

    #La moda ha senso se ci sono almeno 3 pacchetti
    if count > 2:
        try:
            moda = mode(size_list)
        except :
            moda = -1
    else:
        moda = -1

    print("Upstream SIZE LIST: " + str(size_list) + " MODE : " + str(moda) + " COUNT : " + str(count) + " THROUGHPUT : " + str(throughput))
    return moda, count, throughput


def connection_duration(sliding_window):
    count = 0
    # stream matrix = [IP, PORT, IP, PORT]
    stream_matrix = []
    syn_timestamp_list = []
    # Lista principale: (ONLY_SYN se trovo la SYN senza FYN, ONLY_FIN viceversa, durata s trovo la coppia SYN-FIN)
    duration_connection = []
    # Filtra per IP source
    for packet in sliding_window:
        try:
            if packet.ip.src == IOT_DEVICE_IP:
                if packet.tcp.flags_syn.int_value == 1:
                    #syn_timestamp = packet.sniff_timestamp
                    stream = [packet.ip.src, packet.tcp.srcport, packet.ip.dst, packet.tcp.dstport]
                    #print("SYN : ")
                    #print(stream, packet.sniff_timestamp)
                    count = count + 1
                    stream_matrix.append(stream)
                    syn_timestamp_list.append(packet.sniff_timestamp)
        except AttributeError:
            #print("Non trovato l'attributo TCP")
            pass
    #print("Sono stati trovati " + str(len(syn_timestamp_list)) + " SYN")
    #print(stream_matrix)
    #print(syn_timestamp_list)
    count_synfin = 0
    for packet in sliding_window:
        try:
            if packet.ip.dst == IOT_DEVICE_IP:
                if packet.tcp.flags_fin.int_value == 1:
                    fin_timestamp = [packet.sniff_timestamp]
                    stream = [packet.ip.dst, packet.tcp.dstport, packet.ip.src, packet.tcp.srcport ]
                    #print("FIN : ")
                    #print(stream, packet.sniff_timestamp)
                    try:
                        index = stream_matrix.index(stream)
                        #print(packet.sniff_timestamp)
                        #print(syn_timestamp_list[index])
                        duration_connection.append(float(packet.sniff_timestamp) - float(syn_timestamp_list[index]))
                        #stream_matrix.remove(stream)
                        #print("MATRICE : " + str(len(stream_matrix)))
                        #print(stream_matrix)
                        count_synfin = count_synfin + 1
                    except ValueError:
                        duration_connection.append("ONLY_FIN")
                        #print("Trovata una FIN ma non la SYN")

            #stream_matrix.append(stream)
            #syn_timestamp_list.append(syn_timestamp)
        except AttributeError:
            #print("Non trovato l'attributo TCP")
            pass
    #aggiungo i SYN che non hanno FIN
    #for riga in range(len(stream_matrix)):
    for riga in range(len(syn_timestamp_list)-count_synfin):
        duration_connection.append("ONLY_SYN")
    #print("Count delle coppie syn-fin " + str(count_synfin))
    print("Duration of the founded connections : " + str(duration_connection))
    return duration_connection


def make_decision(sliding_window):
    media, count_downstream, throughput_downstream = media_downstream(sliding_window)
    moda, count_upstream, throughput_upstream = moda_upstream(sliding_window)

    # Check IDLE
    if media == 107 or media == -1:
        if moda == 107 or moda == -1:
            if count_downstream == count_upstream:
                return "IDLE"

    # Check RESTARTING
    ntp = False
    for packet in sliding_window:
        if packet.highest_layer == "NTP":
            ntp = True
    count = 0
    if ntp is True or len(connection_duration(sliding_window)) > 2:
        for duration in connection_duration(sliding_window):
            if duration == "ONLY_SYN":
                continue
            if duration == "ONLY_FIN":
                continue
            if duration > 5:
                count = count + 1
        if count < 2:
            #TODO Mancano check Annidati
            return "RESTARTING"
        else:
            print("FATAL: Ci sono " + count + " cnnessioni durature contemporaneamente")
            return "SERIOUS_ANOMALY"


    #Check USER_ACTIVITY
    if media > 107:
        if moda > 107 or moda == -1:
            if throughput_downstream < throughput_upstream:
                if count_downstream > count_upstream:
                    return "USER_ACTIVITY"

    # Check SERIOUS ANOMALY
    if count_downstream + 1 < count_upstream:
        print("FATAL: il conteggio dei pacchetti in upstream è sospetto")
        return "SERIOUS_ANOMALY"

    return "MINOR_ANOMALY"


# CODICE
packets = pyshark.FileCapture(file)
packets_list = list(packets)
print("Packets_LIST : " + str(len(packets_list)) + " Floating Window : 0")

fill_list(packets_list)
STATUS = make_decision(sliding_window)
print("Packets_LIST : " + str(len(packets_list)) + " Floating Window : " + str(len(sliding_window)) + " DECISION : " + STATUS)


while True:
    update_list(packets_list, sliding_window)
    STATUS = make_decision(sliding_window)
    print("Packets_LIST : " + str(len(packets_list)) + " Floating Window : " + str(
        len(sliding_window)) + " DECISION : " + STATUS)
    if len(packets_list) < 20:
        break