from __future__ import print_function
from scapy.all import *
#import slowloris.py
import numpy as np
import collections
import csv
import netifaces
import threading

#############################################################################
#	SNIFFER DE REDE QUE CAUCULA A ENTROPIA DE UMA JANELA DE 80 PACOTES 	    #
#			COM BASE NO TAMANHO DE CADA PACOTE CAPTURADO                    #
#																			#		
#	AUTOR: BRUNO HENRIQUE SCHWENGBER										#						
#	DATA:  16/05/2019														#
#############################################################################

class Sniffer():
	cont=0
	entrada = []
	dest = []
	sport = []
	interface = None
	entropias = []
	cont_detection = 0

	#Funcao responsavel por capturar o tamanho dos pacotes e adicionar
	#ao vetor entrada que deve ser passado para a funcao entropy()
	def pkt_handler(self,pkt): 
		global cont #inicializa a variavel cont puxando do escopo global
		global entrada #inicializa a variavel entrada puxando do escopo global
		global dest
		global sport
		len = pkt.len #captura o valor do tamanho do pacote e adiciona na variavel len
		self.cont=self.cont+1 #contadore e acrescentado em 1 para contagem do tamanho da janela
		self.entrada.append(len) #vetor entrada recebe o valor do tamanho do pacote
		
		dst = pkt.src
		self.dest.append(dst)
		#print(self.dest)
		inport = pkt.sport
		self.sport.append(inport)

		if (self.cont == 50): #verificacao se a quantidade de pacotes ja chego no tamanho da janela (80)
			self.cont=0 #contador e zerado para nova contagem da janela
			self.entropy(self.entrada, self.dest, self.sport) #e feito o calculo da entropia com base nos valores do vetor de entrada
			self.entrada.clear() #vetor de entrada e zerado para novas entradas

	#Funcao que realiza o calculo da entropia com base em um vetor de entrada
	def entropy(self, entrada, dst, sport):
		#print(entrada)
		global entropias #inicializa variavel entropias puxando do escopo global
		global cont_detection
		C = collections.Counter(entrada) #Funcao que conta quantos valores possui o vetor
		count = np.array(list(C.values()),dtype=float) #transforma os valores da lista em float
		prob    = count/count.sum() #calula a probabilidade de cada item dentro do vetor
		shannon = (-prob*np.log2(prob)).sum() #calcula a entropia utilizando as probabilidades
		print("Entropia: ", round(shannon,2)) #imprime o valor da entropia
		#entropias.append(shannon) #adiciona o valor da entropia ao vetor de entropias
		self.deteccao(shannon, dst, sport)

	def deteccao(self, entropia, dst, sport):

		D = collections.Counter(dst)
		count = np.array(list(D.values()), dtype=float)
		prob   = count/count.sum()
		prob = prob.tolist()
		maior = max(prob)
		index = prob.index(maior)

		switch = self.interface.split("-")
		switch = switch[0]
		switch = str(switch)
		destino = dst[index]
		in_porta = sport[index]
		destino = str(destino)
		in_porta = str(in_porta)

		if entropia < 1.5:
			#cont_detection+=
			#if cont_detection < QNT_VERIFICACOES:
			arquivo = open("/home/ubuntu/ryu/flag.txt", "w")
			arquivo.write("1")
			arquivo.close()
			arquivo = open("/home/ubuntu/ryu/apontador.txt", "w")
			arquivo.write(switch+"\n")
			arquivo.write(destino+"\n")
			arquivo.write(in_porta+"\n")
			arquivo.close()
			time.sleep(1)
			arquivo = open("/home/ubuntu/ryu/apontador.txt", "w")
			arquivo.write("0\n\n")
			arquivo.close() 
		else:
			arquivo = open("/home/ubuntu/ryu/flag.txt", "w")
			arquivo.write("0")
			arquivo.close() 			



	def main(self,kwargs, interface):

		#inicia o sniffer da rede, na porta h1-eth0, a funcao prn manda cada pacote
		#recebido para a funcao pkt_handler, filter faz o filtro dos pacotes para 
		#receber somente pacotes TCP

		#threads = []
		#interfaces = netifaces.interfaces()
		#for x in interfaces:
			#t = threading.Thread(target=sniff, args(), kwargs={'iface':x, 'prn':pkt_handler, 'filter':"tcp", ' store':0}).start()
			#threads.append(t)
		self.interface = interface
		sniff(iface=interface, prn=self.pkt_handler, filter="tcp", store=0)


#Inicia o Codigo chamando a funcao principal.
if __name__ == '__main__': 
	interfaces = netifaces.interfaces()
	y = []
	for x in interfaces:
		snif = Sniffer()
		if x != 'lo' and x != 'docker0' and x != 'eth0' and x != 'eth1':
			t = threading.Thread(target=snif.main, args=(snif,x))
			print(t)
			t.start()
			y.append(t)
			
			



