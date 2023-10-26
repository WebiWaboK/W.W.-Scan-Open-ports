import nmap

print("──────▄▀▄─────▄▀▄")
print("─────▄█░░▀▀▀▀▀░░█▄")
print("─▄▄──█░░░░░░░░░░░█──▄▄")
print("█▄▄█─█░░▀░░┬░░▀░░█─█▄▄█")



print("Programa para ver puertos abiertos de una IP")
print(" || By: W.W. ||")


host= input("[+] Introduce la IP objetivo: ")
nm= nmap.PortScanner()
results= nm.scan(host, arguments="-sT -n -Pn -T4")
puertos_abiertos='-p'
count=0
#print(results)

try:   
    print("Host : %s" % host)
    print("State : %s" % nm[host].state())
    for proto in nm[host].all_protocols():
        print("Protocol : %s" % proto)
        lport = nm[host][proto].keys()
        sorted(lport)
        for port in lport:
            print ("port : %s\tstate : %s" % (port, nm[host][proto][port]["state"]))
            if count==0:
                puertos_abiertos= puertos_abiertos+" "+str(port)
                count=1
            else:
                puertos_abiertos= puertos_abiertos+","+str(port)

    print("Puertos Abiertos: "+puertos_abiertos+" "+str(host))
except Exception as e:
    print(f"Error: {e}")
