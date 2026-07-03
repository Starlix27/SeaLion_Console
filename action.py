import os
import time
import sys
import json
import random

class Sealion:
    def __init__(self, name="Foca", width=120, filepath="ascii-art.txt", state_file="sealion_state.json"):
        self.name = name
        self.width = width
        self.filepath = filepath
        self.state_file = state_file
        self.sealion_art = self.load_art()
        self.sealion_mirrored = self.mirror_art(self.sealion_art)
        self.lingua_art = self.load_lingua()
        self.lingua_mirrored = self.mirror_art(self.lingua_art)
        self.art_width = max(len(line.rstrip('\n')) for line in self.sealion_art)
        self.max_x = self.width - self.art_width - 5
        self.x_pos = 0
        self.direction = 1
        self.speed = 2
        self.hunger = 100
        self.happiness = 100
        self.last_message = ""
        self.message_time = 0
        self.running = True
        self.showing_lingua = False
        self.lingua_time = 0
        self.last_action_time = time.time()
        self.action_interval = random.randint(30, 60)  # Azione ogni 30-60 secondi
        
    def load_art(self):
        """Carica il disegno ASCII dal file"""
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                return f.readlines()
        except FileNotFoundError:
            print(f"Errore: file {self.filepath} non trovato!")
            sys.exit(1)
    
    def load_lingua(self):
        """Carica il disegno della linguaccia"""
        try:
            with open("lingua.txt", 'r', encoding='utf-8') as f:
                return f.readlines()
        except FileNotFoundError:
            # Se il file non esiste, usa l'arte normale
            return self.load_art()
    
    def mirror_art(self, art):
        """Crea una versione specchiata del disegno ASCII"""
        mirrored = []
        for line in art:
            line_content = line.rstrip('\n')
            mirrored_line = line_content[::-1]
            mirrored.append(mirrored_line + '\n')
        return mirrored
    
    def get_sealion(self):
        """Ritorna l'ASCII art della foca, specchiato se necessario"""
        # Se è in corso l'azione della linguaccia, mostra quello
        if self.showing_lingua:
            if self.direction == 1:
                return self.lingua_art
            else:
                return self.lingua_mirrored
        
        # Altrimenti mostra l'arte normale
        if self.direction == 1:
            return self.sealion_art
        else:
            return self.sealion_mirrored
    
    def update_position(self):
        """Aggiorna la posizione della foca con rimbalzo agli angoli"""
        self.x_pos += self.direction * self.speed
        
        if self.x_pos >= self.max_x:
            self.x_pos = self.max_x
            self.direction = -1
        elif self.x_pos <= 0:
            self.x_pos = 0
            self.direction = 1
    
    def linguaccia(self):
        """Fa tirare la lingua alla foca per 2 secondi"""
        self.showing_lingua = True
        self.lingua_time = time.time()
        self.last_message = f"{self.name} tira la lingua!"
        self.message_time = time.time()
    
    def check_spontaneous_action(self):
        """Controlla se è il momento di fare un'azione spontanea"""
        if time.time() - self.last_action_time > self.action_interval:
            self.last_action_time = time.time()
            self.action_interval = random.randint(30, 60)
            self.linguaccia()
    
    def update_lingua_status(self):
        """Aggiorna lo stato della linguaccia"""
        if self.showing_lingua and (time.time() - self.lingua_time) > 2:
            self.showing_lingua = False
    
    def read_state(self):
        """Legge lo stato della foca dal file JSON"""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                    self.hunger = state.get('hunger', 100)
                    self.happiness = state.get('happiness', 100)
                    self.name = state.get('name', self.name)
                    
                    # Leggi il nuovo messaggio
                    new_message = state.get('last_message', "")
                    if new_message and new_message != self.last_message:
                        self.last_message = new_message
                        self.message_time = time.time()
                    
                    # Controlla se il gioco è ancora in corso
                    self.running = state.get('running', True)
        except:
            pass
    
    def draw_frame(self):
        """Disegna la cornice attorno al disegno"""
        border_horizontal = "=" * (self.width - 2)
        print(f"+{border_horizontal}+")
    
    def draw_frame_bottom(self):
        """Disegna la cornice inferiore"""
        border_horizontal = "=" * (self.width - 2)
        print(f"+{border_horizontal}+")
    
    def draw_message(self):
        """Mostra il messaggio se recente"""
        border_v = "|"
        
        # Se il messaggio è più vecchio di 2 secondi, non mostrarlo
        if self.message_time and (time.time() - self.message_time) > 2:
            self.last_message = ""
        
        if self.last_message:
            # Formatta il messaggio su multiple righe se necessario
            lines = self.last_message.split('\n')
            for line in lines:
                line_clean = line.strip()
                if line_clean:
                    padding = self.width - 4 - len(line_clean)
                    if padding < 0:
                        line_clean = line_clean[:self.width - 4]
                        padding = 0
                    print(f"{border_v} {line_clean}{' ' * padding} {border_v}")
                else:
                    print(f"{border_v}{' ' * (self.width - 2)}{border_v}")
    
    def draw_status_bar(self):
        """Disegna la barra di stato"""
        border_v = "|"
        status = f"Fame: {self.hunger:3d}% | Felicita: {self.happiness:3d}% | {self.name}"
        
        available_width = self.width - 4
        status_line = f" {status} "
        
        if len(status_line) < available_width:
            status_line += " " * (available_width - len(status_line))
        else:
            status_line = status_line[:available_width]
        
        print(f"{border_v}{status_line}{border_v}")
    
    def animate(self):
        """Anima la foca muovendosi nel terminale"""
        try:
            while self.running:
                os.system('cls' if os.name == 'nt' else 'clear')
                
                # Leggi lo stato aggiornato
                self.read_state()
                
                # Controlla azioni spontanee
                self.check_spontaneous_action()
                
                # Aggiorna lo stato della linguaccia
                self.update_lingua_status()
                
                # Aggiorna posizione
                self.update_position()
                
                # Disegna cornice superiore
                self.draw_frame()
                
                # Mostra il messaggio se presente
                self.draw_message()
                
                # Disegna la foca
                sealion = self.get_sealion()
                border_v = "|"
                for line in sealion:
                    line_content = line.rstrip('\n')
                    padding_right = self.width - 2 - self.x_pos - len(line_content)
                    if padding_right < 0:
                        padding_right = 0
                    print(f"{border_v}{' ' * self.x_pos}{line_content}{' ' * padding_right}{border_v}")
                
                # Disegna cornice inferiore
                self.draw_frame_bottom()
                
                # Disegna barra di status
                self.draw_status_bar()
                
                time.sleep(0.03)
            
            # Se il gioco è finito, mostra il messaggio di uscita
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\nLa foca se ne è andata a nuotare...\n")
            time.sleep(2)
                
        except KeyboardInterrupt:
            print("\nAnimazione terminata!")
            sys.exit(0)

def main():
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        name = "Foca"
    
    print(f"Animazione Sealion - {name} sta nuotando!")
    time.sleep(1)
    
    sealion = Sealion(name=name, width=120)
    sealion.animate()

if __name__ == "__main__":
    main()


