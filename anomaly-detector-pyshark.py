#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Feb 13 13:35:54 2021

@author: rocco
"""
from statistics import mean, mode
import pyshark
import numpy

# DATI
floating_window = []
window_width = 60
shift = 1
#file = 'file-pcapng/traffic-stanby.pcapng'
#file = 'file-pcapng/spegni-accendi-thermostat.pcapng'
file = 'file-pcapng/traffic-with-operations-thermostat.pcapng'

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
            floating_window.append(packet)
            #packets_list.remove(packet)
        else:
            del packets_list[:count]
            #print("There are " + str(len(floating_window)) + " items in the floating window")
            return floating_window


def update_list(packets_list, floating_window):
    count = 0
    riferimento = float(floating_window[0].sniff_timestamp)
    for packet in floating_window:
        relative_time = float(packet.sniff_timestamp) - riferimento
        if relative_time < shift:
            count = count + 1
            #floating_window.remove(packet)
        else:
            del floating_window[:count]
            break
    count = 0
    riferimento = float(floating_window[0].sniff_timestamp) + window_width
    for packet in packets_list:
        relative_time = float(packet.sniff_timestamp) - riferimento
        if relative_time < 0:
            count = count + 1
            floating_window.append(packet)
            #packets_list.remove(packet)
        else:
            del packets_list[:count]
            return packets_list, floating_window


def media_downstream(floating_window):
    count = 0
    size_list = []
    for packet in floating_window:
        count = count + 1
        try:
            #print("count : " + str(count) + " IP_DST : " + packet.ip.dst + " Protocol : " + packet.highest_layer + " Packet length: " + str(packet.length))
            if packet.ip.dst == IOT_DEVICE_IP:
                if packet.highest_layer == "SSL":
                    size_list.append(float(packet.length))
        except AttributeError:
            pass
            #print("Continua...")
    try:
        media = mean(size_list)
        count_downstream = len(size_list)
    except:
        media = -1
        count_downstream = -1
    print("Downstream SIZE LIST: " + str(size_list) + " AVERAGE : " + str(media))
    return media, count_downstream


def moda_upstream(floating_window):
    count = 0
    size_list = []
    for packet in floating_window:
        count = count + 1
        try:
            #print("count : " + str(count) + " IP_DST : " + packet.ip.dst + " Protocol : " + packet.highest_layer + " Packet length: " + str(packet.length))
            if packet.ip.src == IOT_DEVICE_IP:
                if packet.highest_layer == "SSL":
                    size_list.append(float(packet.length))
        except AttributeError:
            pass
            #print("Continua...")
    try:
        moda = mode(size_list)
        count_upstream = len(size_list)
    except:
        moda = -1
        count_upstream = -1

    print("Upstream SIZE LIST: " + str(size_list) + " MODE : " + str(moda))
    return moda, count_upstream


def connection_duration(floating_window):
    count = 0
    # stream matrix = [IP, PORT, IP, PORT]
    stream_matrix = []
    syn_timestamp_list = []
    # Lista principale: (ONLY_SYN se trovo la SYN senza FYN, ONLY_FIN viceversa, durata s trovo la coppia SYN-FIN)
    duration_connection = []
    # Filtra per IP source
    for packet in floating_window:
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
    for packet in floating_window:
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
                        print("Trovata una FIN ma non la SYN")

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


def make_decision(floating_window):
    media, count_downstream = media_downstream(floating_window)
    moda, count_upstream = moda_upstream(floating_window)

    # Check IDLE
    if media == 107 or media == -1:
        if moda == 107 or moda == -1:
            if count_downstream == count_downstream:
                STATUS = "IDLE"
                return STATUS

    # Check RESTARTING
    ntp = False
    for packet in floating_window:
        if packet.highest_layer == "NTP":
            ntp = True
    count = 0
    if ntp is True or len(connection_duration(floating_window)) > 2:
        for duration in connection_duration(floating_window):
            if duration == "ONLY_SYN": continue
            if duration == "ONLY_FIN": continue
            if duration > 5:
                count = count + 1
        if count < 2:
            #TODO Mancano check Annidati
            return "RESTARTING"


    #Check USER_ACTIVITY
    if media > 107 :
        if moda > 107:
            if count_downstream > count_upstream:
                return "USER_ACTIVITY"

    # Check SERIOUS ANOMALY
    if count_downstream + 1 < count_upstream:
        return "SERIOUS_ANOMALY"
    #TODO altro check sulla durata delle sessione

    return "MINOR_ANOMALY"


# CODICE
packets = pyshark.FileCapture(file)
packets_list = list(packets)
print("Packets_LIST : " + str(len(packets_list)) + " Floating Window : 0")

fill_list(packets_list)
STATUS = make_decision(floating_window)
print("Packets_LIST : " + str(len(packets_list)) + " Floating Window : " + str(len(floating_window)) + " DECISION : " + STATUS)


while True:
    update_list(packets_list, floating_window)
    STATUS = make_decision(floating_window)
    print("Packets_LIST : " + str(len(packets_list)) + " Floating Window : " + str(
        len(floating_window)) + " DECISION : " + STATUS)
    if len(packets_list) < 20:
        break
