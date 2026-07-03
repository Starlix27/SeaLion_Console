import json
import os
import subprocess
import sys
import time
import threading

class sealion():
    def __init__(self, name):
        self.name = name
        self.hunger = 100
        self.happiness = 100
        self.state_file = "sealion_state.json"
        self.save_state()
        self.time_thread_running = False
        
    def save_state(self, message=""):
        """Salva lo stato della foca su file JSON"""
        state = {
            'name': self.name,
            'hunger': self.hunger,
            'happiness': self.happiness,
            'last_message': message,
            'running': True
        }
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f)
        except Exception as e:
            print(f"Errore nel salvare lo stato: {e}")
    
    def eat(self, food):
        if food == "fish":
            self.hunger = min(100, self.hunger + 20)
            self.happiness = min(100, self.happiness + 10)
            return f"Munch munch! {self.name} adora i pesci!"
        elif food == "junk":
            self.hunger = max(0, self.hunger - 10)
            self.happiness = max(0, self.happiness - 20)
            return f"Bleah! {self.name} non gradisce il cibo scadente!"
        else:
            return f"Non so cosa sia '{food}'"
        
    def shake_head(self):
        if self.happiness > 35:
            return f"{self.name} scuote la testa velocemente!"
        else:
            return f"{self.name} non ha voglia di giocare"
    
    def gira(self):
        if self.happiness > 35:
            return f"{self.name} fa un giro su se stessa!"
        else:
            return f"{self.name} non ha voglia di girare"
            
    def happy_hi(self):
        if self.happiness > 50:
            return f"Ouh! Ouh! Ouh! {self.name} ti saluta felice!"
        else:
            return f"Fssss Fssss... {self.name} non è in vena di giocare"
    
    def time_passes(self, seconds):
        """Simula il passare del tempo, riducendo fame e felicità"""
        self.hunger = max(0, self.hunger - (seconds // 5))
        self.happiness = max(0, self.happiness - (seconds // 5) * 2)
        self.save_state()

    def sleep(self):
        self.hunger = max(0, self.hunger - 5)
        self.happiness = min(100, self.happiness + 15)
        return f"{self.name} sta dormendo... Zzzzz"
    
    def process_command(self, cmd):
        """Processa i comandi dell'utente"""
        cmd = cmd.strip().lower()
        
        if cmd.startswith("eat "):
            food = cmd[4:]
            result = self.eat(food)
        elif cmd == "hello" or cmd == "ciao":
            result = self.happy_hi()
        elif cmd == "shake":
            result = self.shake_head()
        elif cmd == "gira":
            result = self.gira()
        elif cmd == "sleep":
            result = self.sleep()
        elif cmd == "status":
            result = f"Fame: {self.hunger}% | Felicita: {self.happiness}%"
        elif cmd == "help":
            result = """
Comandi disponibili:
  * eat fish     - Dai pesce alla foca
  * eat junk     - Dai cibo scadente
  * hello/ciao   - Saluta la foca
  * shake        - Fai scuotere la testa
  * gira         - Fai girare la foca
  * sleep        - La foca dorme
  * status       - Mostra i valori
  * quit/exit    - Esci
"""
        elif cmd == "quit" or cmd == "exit":
            return "EXIT"
        else:
            result = f"Comando non riconosciuto: '{cmd}'. Scrivi 'help'"
        
        self.save_state(result)
        return result
    
    def start_time_thread(self):
        """Avvia un thread che fa passare il tempo ogni 10 secondi"""
        def time_loop():
            while self.time_thread_running:
                time.sleep(10)
                if self.time_thread_running:
                    self.time_passes(10)
        
        self.time_thread_running = True
        thread = threading.Thread(target=time_loop, daemon=True)
        thread.start()
    
    def stop_time_thread(self):
        """Ferma il thread del tempo"""
        self.time_thread_running = False

def main():
    print("\n" + "="*50)
    print("BENVENUTO NEL MONDO DELLE FOCHE")
    print("="*50 + "\n")
    
    # Chiedi il nome della foca
    while True:
        name = input("Come vuoi chiamare la tua foca? > ").strip()
        if name:
            break
        print("Per favore, inserisci un nome valido!")
    
    # Crea l'istanza della foca
    foca = sealion(name)
    print(f"\n{name} è stata evocata!\n")
    time.sleep(1)
    
    # Avvia il thread del tempo
    foca.start_time_thread()
    
    # Avvia l'animazione in un nuovo terminale
    print("Avvio l'animazione della foca...\n")
    time.sleep(1)
    
    try:
        if os.name == 'nt':  # Windows
            subprocess.Popen(['start', 'cmd', '/k', f'python action.py {name}'], shell=True)
        else:  # Linux/Mac
            subprocess.Popen(['gnome-terminal', '--', 'python', 'action.py', name])
    except Exception as e:
        print(f"Errore nell'avvio dell'animazione: {e}")
        print("Avvia manualmente: python action.py {name}")
    
    print("\n" + "="*50)
    print(f"Stai giocando con {name}!")
    print("Scrivi 'help' per l'elenco dei comandi")
    print("="*50 + "\n")
    
    # Loop dei comandi
    try:
        while True:
            cmd = input(f"{name} > ").strip()
            
            if not cmd:
                continue
            
            response = foca.process_command(cmd)
            
            if response == "EXIT":
                print(f"\n{name} se ne è andata a nuotare...")
                # Segnala la chiusura al processo di animazione
                state = {
                    'name': foca.name,
                    'hunger': foca.hunger,
                    'happiness': foca.happiness,
                    'last_message': '',
                    'running': False
                }
                try:
                    with open(foca.state_file, 'w', encoding='utf-8') as f:
                        json.dump(state, f)
                except:
                    pass
                foca.stop_time_thread()
                time.sleep(0.5)
                break
            
            print(f"\n{response}\n")
         
    except KeyboardInterrupt:
        print(f"\n\n{name} se ne è andata a nuotare...")
        # Segnala la chiusura al processo di animazione
        state = {
            'name': foca.name,
            'hunger': foca.hunger,
            'happiness': foca.happiness,
            'last_message': '',
            'running': False
        }
        try:
            with open(foca.state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f)
        except:
            pass
        foca.stop_time_thread()
        sys.exit(0)

if __name__ == "__main__":
    main()

