#!/usr/bin/env python3
# mitre_attack_explorer.py - Client per esplorare il MITRE ATT&CK framework
# Questo script mostra come utilizzare la libreria mitreattack-python

import sys
import os
from pprint import pprint

# Verifica se la libreria mitreattack-python è installata
try:
    from mitreattack.stix20 import MitreAttackData
except ImportError:
    print("La libreria mitreattack-python non è installata.")
    print("Installala con: pip install mitreattack-python")
    sys.exit(1)


# Funzione per scaricare il dataset MITRE ATT&CK se non è presente
def download_attack_data():
    import requests
    import json

    print("Scaricamento del dataset MITRE ATT&CK Enterprise...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open("enterprise-attack.json", "wb") as f:
                f.write(response.content)
            print("Dataset scaricato con successo.")
            return True
        else:
            print(f"Errore nel download: {response.status_code}")
            return False
    except Exception as e:
        print(f"Errore durante il download: {str(e)}")
        return False


# Funzione per visualizzare le tecniche relative a una tattica
def display_techniques_for_tactic(mitre_data, tactic_id):
    tactics = mitre_data.get_tactics()

    # Trova la tattica specificata
    tactic = next((t for t in tactics if t.id == tactic_id), None)

    if not tactic:
        print(f"Tattica {tactic_id} non trovata.")
        return

    print(f"\n{'=' * 40}")
    print(f"TECNICHE PER LA TATTICA: {tactic.name} ({tactic.id})")
    print(f"{'=' * 40}")
    print(f"Descrizione: {tactic.description[:150]}...")
    print(f"{'=' * 40}")

    # Ottieni tutte le tecniche associate a questa tattica
    techniques = mitre_data.get_techniques_by_tactic(tactic_id)
    techniques = mitre_data.remove_revoked_deprecated(techniques)

    if not techniques:
        print("Nessuna tecnica trovata per questa tattica.")
        return

    # Visualizza le tecniche
    for i, technique in enumerate(techniques, 1):
        print(f"{i}. {technique.name} ({technique.id})")
        print(
            f"   Descrizione: {technique.description[:100]}..." if technique.description else "   Nessuna descrizione")

        # Controlla se la tecnica ha sottotecniche
        subtechniques = getattr(technique, 'subtechniques', [])
        if subtechniques:
            print(f"   Sottotecniche:")
            for j, sub in enumerate(subtechniques, 1):
                print(f"      {i}.{j} {sub.name} ({sub.id})")
        print()


# Funzione per visualizzare i dettagli di una tecnica specifica
def display_technique_details(mitre_data, technique_id):
    # Ottieni la tecnica
    technique = mitre_data.get_object_by_attack_id(technique_id, 'attack-pattern')

    if not technique:
        print(f"Tecnica {technique_id} non trovata.")
        return

    print(f"\n{'=' * 40}")
    print(f"DETTAGLI DELLA TECNICA: {technique.name} ({technique.id})")
    print(f"{'=' * 40}")

    # Visualizza la descrizione
    if hasattr(technique, 'description'):
        description = technique.description
        # Limita la descrizione a 500 caratteri per leggibilità
        if len(description) > 500:
            description = description[:500] + "..."
        print(f"Descrizione: {description}")

    # Visualizza i gruppi che usano questa tecnica
    groups_using = mitre_data.get_groups_using_technique(technique_id)
    if groups_using:
        print("\nGruppi che utilizzano questa tecnica:")
        for i, group_rel in enumerate(groups_using, 1):
            group = group_rel['object']
            print(f"{i}. {group.name} ({group.id})")

    # Visualizza il software che implementa questa tecnica
    software_implementing = mitre_data.get_software_implementing_technique(technique_id)
    if software_implementing:
        print("\nSoftware che implementa questa tecnica:")
        for i, sw_rel in enumerate(software_implementing, 1):
            sw = sw_rel['object']
            print(f"{i}. {sw.name} ({sw.id}) - Tipo: {sw.type}")

    # Visualizza le mitigazioni
    mitigations = mitre_data.get_mitigations_by_technique(technique_id)
    mitigations = mitre_data.remove_revoked_deprecated(mitigations)
    if mitigations:
        print("\nMitigazioni raccomandate:")
        for i, mitigation in enumerate(mitigations, 1):
            print(f"{i}. {mitigation.name} ({mitigation.id})")

    print(f"{'=' * 40}")


# Funzione principale per esplorare il MITRE ATT&CK framework
def main():
    # Banner di avvio
    print("\n" + "=" * 60)
    print("ESPLORATORE MITRE ATT&CK - USO EDUCATIVO")
    print("=" * 60)

    # Verifica se il dataset è presente
    if not os.path.exists("enterprise-attack.json"):
        print("Dataset MITRE ATT&CK non trovato.")
        if not download_attack_data():
            print("Impossibile continuare senza il dataset.")
            sys.exit(1)

    # Carica il dataset
    try:
        mitre_data = MitreAttackData("enterprise-attack.json")
        print("Dataset MITRE ATT&CK caricato con successo.")
    except Exception as e:
        print(f"Errore nel caricamento del dataset: {str(e)}")
        sys.exit(1)

    # Menu principale
    while True:
        print("\nMENU PRINCIPALE:")
        print("1) Visualizza tutte le tattiche")
        print("2) Visualizza tecniche per una tattica")
        print("3) Visualizza dettagli di una tecnica")
        print("4) Cerca tecniche per parola chiave")
        print("5) Esci")

        choice = input("\nSeleziona un'opzione (1-5): ")

        if choice == '1':
            # Visualizza tutte le tattiche
            tactics = mitre_data.get_tactics()
            tactics = mitre_data.remove_revoked_deprecated(tactics)

            print("\nTATTICHE NEL FRAMEWORK MITRE ATT&CK:")
            for i, tactic in enumerate(tactics, 1):
                print(f"{i}. {tactic.name} ({tactic.id})")
                print(
                    f"   Descrizione: {tactic.description[:100]}..." if tactic.description else "   Nessuna descrizione")
                print()

        elif choice == '2':
            # Visualizza tecniche per una tattica
            tactics = mitre_data.get_tactics()
            tactics = mitre_data.remove_revoked_deprecated(tactics)

            print("\nTATTICHE DISPONIBILI:")
            for i, tactic in enumerate(tactics, 1):
                print(f"{i}. {tactic.name} ({tactic.id})")

            try:
                index = int(input("\nSeleziona il numero della tattica: ")) - 1
                if 0 <= index < len(tactics):
                    display_techniques_for_tactic(mitre_data, tactics[index].id)
                else:
                    print("Selezione non valida.")
            except ValueError:
                print("Inserisci un numero valido.")

        elif choice == '3':
            # Visualizza dettagli di una tecnica
            technique_id = input("\nInserisci l'ID della tecnica (es. T1046): ")
            display_technique_details(mitre_data, technique_id)

        elif choice == '4':
            # Cerca tecniche per parola chiave
            keyword = input("\nInserisci la parola chiave da cercare: ")

            print(f"\nRicerca di tecniche con la parola chiave '{keyword}':")
            techniques = mitre_data.get_objects_by_content(keyword, 'attack-pattern')
            techniques = mitre_data.remove_revoked_deprecated(techniques)

            if not techniques:
                print("Nessuna tecnica trovata con questa parola chiave.")
            else:
                print(f"Trovate {len(techniques)} tecniche:")
                for i, technique in enumerate(techniques, 1):
                    print(f"{i}. {technique.name} ({technique.id})")
                    if hasattr(technique, 'description'):
                        # Cerca la parola chiave nella descrizione e mostra il contesto
                        desc = technique.description.lower()
                        keyword_lower = keyword.lower()
                        if keyword_lower in desc:
                            pos = desc.find(keyword_lower)
                            start = max(0, pos - 50)
                            end = min(len(desc), pos + len(keyword_lower) + 50)
                            context = "..." + desc[start:end] + "..."
                            print(f"   Contesto: {context}")
                    print()

        elif choice == '5':
            print("\nGrazie per aver utilizzato l'Esploratore MITRE ATT&CK!")
            break

        else:
            print("Opzione non valida. Riprova.")


if __name__ == "__main__":
    main()