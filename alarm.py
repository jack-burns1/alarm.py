#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

incident_number = 0

def packetcallback(packet):
  try:
     
     global incident_number
     if packet.dport == 139 or packet.dport == 445:
        incident_number += 1
        print("ALERT #"+ str(incident_number) + ": SMB protocol is detected from " + str(packet[IP].src) + " (" + str(packet.dport) + ")!")

     elif packet[TCP].flags == "F":
        incident_number += 1
        print("ALERT #"+ str(incident_number) +": FIN scan is detected from " + str(packet[IP].src) + " (" + str(packet.dport) + ")!")
     
     elif packet[TCP].flags == "":
        incident_number += 1
        print("ALERT #"+ str(incident_number) +": NULL scan is detected from " + str(packet[IP].src) + " (" + str(packet.dport) + ")!")
     
     elif packet[TCP].flags == "FPU":
        incident_number += 1
        print("ALERT #"+ str(incident_number) +": Xmas scan is detected from " + str(packet[IP].src) + " (" + str(packet.dport) + ")!")
     
     elif "nikto" in packet[TCP].load.decode("ascii").strip().lower():
        incident_number += 1
        print("ALERT #"+ str(incident_number) +": Nikto scan is detected from " + str(packet[IP].src) + " (" + str(packet.dport) + ")!")
     
     elif packet.dport == 80:
        pload = str(packet.payload)
        i = pload.index("Authorization: Basic")
        if i:
          i +=21
          cred = ""

          while pload[i] != "\\":
            cred += pload[i]
            i+= 1
          cred = base64.b64decode(cred).decode('utf-8')
          user = cred[0:cred.index(":")]
          pword = cred[cred.index(":") + 1:]
          incident_number += 1
          print("ALERT #"+ str(incident_number) +": Usernames and passwords sent in-the-clear (" + str(packet.dport) + ") (username:" + user, "password:" + pword + ")")

     elif packet.dport == 21:
        pload = packet.load.decode("ascii").strip()

        if "USER" in pload:
          user = pload[4:]
          incident_number +=1
          print("ALERT #"+ str(incident_number) +": Username sent in-the-clear (" + str(packet.dport) + ") (username:" + str(user) + ")") 

        elif "PASS" in pload:
          pword = pload[4:]
          incident_number += 1
          print("ALERT #"+ str(incident_number) +": Password sent in-the-clear (" + str(packet.dport) + ") (password:" + str(pword) + ")") 
           
     elif packet.dport == 143:
       pload = packet.load.decode("ascii")
       i = pload.index("LOGIN")
       user = ""
       pword = ""
       if i:
         i += 6
         while pload[i] != " ":
           user += pload[i]
           i+= 1

         i += 2
         while pload[i] != "\"":
           pword += pload[i]
           i+= 1
           
         incident_number += 1
         print("ALERT #" + str(incident_number) + ": Usernames and passwords sent in-the-clear (" + str(packet.dport) + ") (username:" + str(user), "password:" + str(pword) + ")")
  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()

if args.pcapfile:
  print("args.pcapfile")
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")

