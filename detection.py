from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import string
import threading
import time
import os

def _ler_arquivo():
        ant = []
        while True:
            
            arquivo = open("flag.txt","r")
            conteudo = arquivo.read()
            arquivo.close()
            if int(conteudo) == 1 :
                drop = open("apontador.txt", "r")
                switch = drop.readline()
                eth_dst= drop.readline()
                porta = drop.readline()
                drop.close()
                if not ant:
                    print "FLUXO DELETADO \n-- SWITCH " + str(switch) + "-- PORTA " + str(porta) + "-- DESTINO " +str(eth_dst)
                    string = "sudo ovs-ofctl del-flows " + str(switch)  + " in_port="+ str(porta)+",dl_dst="+str(eth_dst)
                    ant.append(switch)
                    ant.append(porta)
                    ant.append(eth_dst)
                if switch != ant[0] or porta != ant[1] or eth_dst != ant[1]:
                    print "FLUXO DELETADO \n-- SWITCH " + str(switch) + "-- PORTA " + str(porta) + "-- DESTINO " +str(eth_dst)
                    string = "sudo ovs-ofctl del-flows " + str(switch)  + " in_port="+ str(porta)+",dl_dst="+str(eth_dst)
                    ant = []
                    ant.append(switch)
                    ant.append(porta)
                    ant.append(eth_dst)
                os.system(string)
                string = "A=`ps -ef | grep slowloris | awk '{print $2}'`;sudo kill -9 $A"
                os.system(string)
   
            else:
                print 'SEM ATAQUE'    
            time.sleep(2)

            

class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        #self.datapaths = {}
        #self.monitor_thread = hub.spawn(self._monitor)
        threading.Thread(target=_ler_arquivo).start()
        #thread.start_new_thread(_ler_arquivo)
