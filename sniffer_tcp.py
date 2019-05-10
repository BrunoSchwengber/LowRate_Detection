from __future__ import print_function
from scapy.all import *
import slowloris.py
import numpy as np
import collections
import csv


cont=0
entrada = []
entropias = []

#Funcao responsavel por capturar o tamanho dos pacotes e adicionar
#ao vetor entrada que deve ser passado para a funcao entropy()
def pkt_handler(pkt): 
	global cont #inicializa a variavel cont puxando do escopo global
	global entrada #inicializa a variavel entrada puxando do escopo global
	len = pkt.len #captura o valor do tamanho do pacote e adiciona na variavel len
	cont=cont+1 #contadore e acrescentado em 1 para contagem do tamanho da janela
	entrada.append(len) #vetor entrada recebe o valor do tamanho do pacote
	if (cont == 80): #verificacao se a quantidade de pacotes ja chego no tamanho da janela (80)
		cont=0 #contador e zerado para nova contagem da janela
		entropy(entrada) #e feito o calculo da entropia com base nos valores do vetor de entrada
		entrada.clear() #vetor de entrada e zerado para novas entradas

#Funcao que realiza o calculo da entropia com base em um vetor de entrada
def entropy(entrada):
	#print(entrada)
	global entropias #inicializa variavel entropias pixando do escopo global
	C = collections.Counter(entrada) #Funcao que conta quantos valores possui o vetor
	count = np.array(list(C.values()),dtype=float) #transforma os valores da lista em float
	prob    = count/count.sum() #calula a probabilidade de cada item dentro do vetor
	shannon = (-prob*np.log2(prob)).sum() #calcula a entropia utilizando as probabilidades
	print("Entropia: ", round(shannon,2)) #imprime o valor da entropia
	entropias.append(shannon) #adiciona o valor da entropia ao vetor de entropias


def main():

	#inicia o sniffer da rede, na porta h1-eth0, a funcao prn manda cada pacote
	#recebido para a funcao pkt_handler, filter faz o filtro dos pacotes para 
	#receber somente pacotes TCP
	sniff(iface="h1-eth0", prn=pkt_handler, filter="tcp", store=0)


#Inicia o Codigo chamando a funcao principal.
if __name__ == '__main__': 
	main()



