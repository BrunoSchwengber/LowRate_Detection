from __future__ import print_function
from scapy.all import *
import numpy as np
import collections
import csv


cont=0
entrada = []
entropias = []


def pkt_handler(pkt):
	global cont
	global entrada
	len = pkt.len
	cont=cont+1
	entrada.append(len)
	if (cont == 80):
		cont=0
		entropy(entrada)
		entrada.clear()


def entropy(entrada):
	#print(entrada)
	global entropias
	C = collections.Counter(entrada)
	count = np.array(list(C.values()),dtype=float)
	prob    = count/count.sum()
	shannon = (-prob*np.log2(prob)).sum()
	print("Entropia: ", round(shannon,2))
	entropias.append(shannon)
	

def main():
	sniff(iface="h1-eth0", prn=pkt_handler, filter="tcp", store=0)

if __name__ == '__main__': 
	main()



