import subprocess
import os
import platform
import requests
import psutil
import socket
import re
import json
import hashlib
import random
from concurrent.futures import ThreadPoolExecutor

# Détermine le système d'exploitation utilisé
def get_os():
    return platform.system().lower()

# Vérifie si une commande est disponible sur le système
def is_command_available(command):
    try:
        subprocess.check_output(["which", command], stderr=subprocess.STDOUT, text=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        print(f"Erreur lors de la vérification de la disponibilité de la commande {command}: {e}")
        return False

# Obtient l'adresse IP de la passerelle par défaut
def get_default_gateway(interface_name=None):
    try:
        output = subprocess.check_output("ip route show default", shell=True, text=True)
        matches = re.search(r"via ([\d.]+)", output)
        if matches:
            return matches.group(1)
        else:
            print("Aucune passerelle par défaut trouvée.")
            return "Inconnu"
    except Exception as e:
        print(f"Erreur lors de la récupération de l'adresse de la passerelle : {e}")
        return "Inconnu"

# Obtient le nom d'hôte pour une adresse IP donnée
def get_hostname_by_ip(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "Nom d'hôte inconnu"
    except socket.gaierror:
        return "Erreur de résolution d'adresse"
    except Exception as e:
        print(f"Erreur inattendue lors de la résolution de l'adresse IP {ip_address}: {e}")
        return "Erreur lors de la résolution du nom d'hôte"

# Convertit un masque de sous-réseau en notation CIDR
def convert_subnet_to_cidr(subnet):
    try:
        return sum([bin(int(x)).count("1") for x in subnet.split(".")])
    except Exception as e:
        print(f"Erreur lors de la conversion du masque de sous-réseau en notation CIDR : {e}")
        return 0

# Liste toutes les interfaces réseau disponibles
def list_network_interfaces():
    try:
        return psutil.net_if_addrs()
    except Exception as e:
        print(f"Erreur lors de la récupération des interfaces réseau : {e}")
        return {}

# Permet à l'utilisateur de choisir une interface réseau
def choose_network_interface(interface_name=None):
    interfaces = list_network_interfaces()
    if not interfaces:
        print("Aucune interface réseau disponible.")
        return None, None, None, None

    if interface_name and interface_name in interfaces:
        selected_interface = interface_name
    else:
        print("Interfaces réseau disponibles :")
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface}")
        try:
            choice = int(input("Choisissez une interface (numéro) : "))
            selected_interface = list(interfaces.keys())[choice - 1]
        except (ValueError, IndexError) as e:
            print("Choix invalide. Veuillez sélectionner un numéro valide.")
            return None, None, None, None
        except Exception as e:
            print(f"Erreur inattendue lors de la sélection de l'interface réseau : {e}")
            return None, None, None, None

    gateway_ip = get_default_gateway(selected_interface)
    gateway_hostname = get_hostname_by_ip(gateway_ip)
    for addr in interfaces[selected_interface]:
        if addr.family == socket.AF_INET:
            ip_address, netmask = addr.address, addr.netmask
            return selected_interface, ip_address, netmask, gateway_ip, gateway_hostname

    print("Erreur : Impossible de récupérer les détails de l'interface réseau sélectionnée.")
    return None, None, None, None, None

# Change l'adresse MAC de l'interface spécifiée
def change_mac_address(interface):
    if not interface:
        print("Aucune interface réseau sélectionnée.")
        return False

    try:
        old_mac = get_mac_address(interface)
        new_mac = "02:00:00:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
        subprocess.check_call(["sudo", "ifconfig", interface, "down"])
        subprocess.check_call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
        subprocess.check_call(["sudo", "ifconfig", interface, "up"])
        print(f"Adresse MAC de {interface} changée de {old_mac} en {new_mac}")
        return True
    except Exception as e:
        print(f"Erreur lors du changement d'adresse MAC : {e}")
        return False

# Obtient l'adresse MAC de l'interface spécifiée
def get_mac_address(interface):
    try:
        result = subprocess.run(["cat", f"/sys/class/net/{interface}/address"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"Erreur lors de la récupération de l'adresse MAC : {e}")
        return "inconnue"

# Vérifie si un hôte est actif en envoyant un ping
def is_host_up(ip_address):
    try:
        socket.gethostbyaddr(ip_address)
        return True
    except socket.herror:
        return False
    except Exception as e:
        print(f"Erreur lors de la vérification de l'hôte {ip_address}: {e}")
        return False

# Vérifie l'état des ports sur une adresse IP
def check_port(ip, ports=[80, 81, 443, 22, 21, 23, 25, 53, 110, 145, 135, 137, 139, 3389, 1433, 3306, 5900, 8080, 8443]):
    results = []

    def check_single_port_unix(port):
        command = ["nc", "-zv", ip, str(port)]
        try:
            subprocess.run(command, check=True, stderr=subprocess.STDOUT)
            return "ouvert"
        except subprocess.CalledProcessError:
            return "fermé ou filtré"
        except Exception as e:
            return f"Erreur: {e}"

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_single_port_unix, ports))

    port_names = {
        80: "HTTP (port : 80)",
        81: "Alternate HTTP (port : 81)",
        443: "HTTPS (port : 443)",
        22: "SSH (port : 22)",
        21: "FTP (port : 21)",
        23: "Telnet (port : 23)",
        25: "SMTP (port : 25)",
        53: "DNS (port : 53)",
        110: "POP3 (port : 110)",
        145: "IMAP (port : 145)",
        135: "RPC (port : 135)",
        137: "NetBIOS Name Service (port : 137)",
        139: "NetBIOS Session Service (port : 139)",
        3389: "Remote Desktop Protocol (port : 3389)",
        1433: "Microsoft SQL Server (port : 1433)",
        3306: "MySQL (port : 3306)",
        5900: "VNC (port : 5900)",
        8080: "HTTP Alternate (port : 8080)",
        8443: "HTTPS Alternate (port : 8443)",
    }
    results_with_names = [
        f"{port_names.get(port, f'Port {port}')} {status}" for port, status in zip(ports, results)
    ]
    return "\n".join(results_with_names)

# Extrait les versions des services à partir des résultats Nmap
def extract_versions(nmap_output):
    versions = {}
    for line in nmap_output.split('\n'):
        if '/tcp' in line and 'open' in line:
            parts = line.split()
            port = parts[0]
            service = parts[2]
            version = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'
            versions[port] = {'service': service, 'version': version}
    return versions

# Recherche des CVE pour un service et une version donnés
def search_cve(service, version):
    try:
        url = f"https://cve.circl.lu/api/search/{service}/{version}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(f"Aucune CVE trouvée pour {service} {version}")
            return [f"Aucune CVE trouvée pour {service} {version}"]
        return []
    except requests.RequestException as e:
        print(f"Erreur lors de la recherche des CVE pour {service} {version}: {e}")
        return [f"Erreur lors de la recherche des CVE pour {service} {version}: {e}"]

# Effectue un scan Nmap sur une adresse IP avec les paramètres spécifiés
def nmap(ip_address, intensity, scan_type):
    print(f"\nScan NMAP sur {ip_address} avec une intensité de {intensity} et un type de scan {scan_type}")
    nmap_path = "nmap"
    command = [nmap_path]

    if intensity == "1":
        command.extend(["-T2"])
    elif intensity == "2":
        command.extend(["-T4"])
    elif intensity == "3":
        command.extend(["-T5"])

    scan_options = {
        "1": (["-sV"], "Détection de la version des services."),
        "2": (["-sS"], "Scan SYN, rapide et moins susceptible de déclencher des alertes de sécurité."),
        "3": (["-A"], "Scan approfondi, incluant la détection de version, les scripts de détection, et la détection d'OS."),
        "4": (["--script", "vuln"], "Détection de vulnérabilités connues sur les services."),
        "5": (["-p-", "-sV"], "Scan de tous les ports (1-65535) avec détection de version de service."),
        "6": (["-sn"], "Ping scan pour vérifier si l'hôte est en ligne sans scanner les ports."),
        "7": (["-sX"], "Scan XMAS pour identifier les ports ouverts en envoyant des paquets avec les flags FIN, PSH et URG."),
        "8": (["--top-ports", "20", "-sV"], "Scan des 20 ports les plus courants avec détection de version des services."),
    }

    if scan_type in scan_options:
        command.extend(scan_options[scan_type][0])
        explanation = scan_options[scan_type][1]
    else:
        print("Type de scan non valide.")
        return "", {}, {}

    command.extend(["-oN", f"nmap_result_{ip_address}.txt", ip_address])

    print(explanation)
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Scan terminé.")
        versions = extract_versions(result.stdout)
        cve_results = {}
        for port, info in versions.items():
            cve_results[port] = search_cve(info['service'], info['version'])
        return result.stdout, versions, cve_results
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du scan Nmap sur {ip_address}: {e}")
        return "", {}, {}
    except Exception as e:
        print(f"Erreur inattendue lors du scan Nmap sur {ip_address}: {e}")
        return "", {}, {}

# Capture le trafic réseau sur une interface et une durée spécifiées
def capture_traffic(interface="any", duration=10, ip_address=""):
    pcap_file = f"capture_{ip_address or 'network'}.pcap"
    command = ["tcpdump", "-i", interface, "-w", pcap_file, "-G", str(duration), "-W", "1"]
    if ip_address:
        command += [f"host {ip_address}"]
    try:
        print(f"Début de la capture de trafic sur {ip_address or 'tout le réseau'}...")
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Capture terminée. Fichier sauvegardé: {pcap_file}")
        return pcap_file
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la capture de trafic: {e}")
        return "Erreur de capture"
    except Exception as e:
        print(f"Erreur inattendue lors de la capture de trafic : {e}")
        return "Erreur de capture"

# Scanne le réseau local
def scan_local_network():
    selected_interface, ip_address, netmask, gateway_ip, gateway_hostname = choose_network_interface()
    if not ip_address or not netmask or not gateway_ip:
        print("Erreur: Impossible de récupérer les détails de l'interface réseau.")
        return

    change_mac = input("Souhaitez-vous changer l'adresse MAC de l'interface sélectionnée ? (oui/non) : ").strip().lower()
    if change_mac == "oui":
        if change_mac_address(selected_interface):
            print(f"Adresse MAC de l'interface {selected_interface} changée avec succès.")
        else:
            print("Échec du changement d'adresse MAC. Utilisation de l'adresse MAC actuelle.")

    network = f"{ip_address}/{convert_subnet_to_cidr(netmask)}"
    print(f"Scan du réseau local: {network}")

    try:
        active_hosts_output = subprocess.check_output(["nmap", "-sn", network], text=True)
        active_hosts_info = re.findall(r"Nmap scan report for (.+?)\n", active_hosts_output)
        print("Adresses IP et noms d'hôtes actifs:")
        for host_info in active_hosts_info:
            print(host_info)

        print(f"Gateway IP: {gateway_ip}")

        intensity = input("Choisissez l'intensité du scan (1: Faible, 2: Moyen, 3: Élevé) : ")
        print("""
        Choisissez le type de scan :
        1 - Détection de version des services
        2 - Scan SYN (rapide et discret)
        3 - Scan approfondi (détection de version, scripts de détection, OS)
        4 - Détection de vulnérabilités connues
        5 - Scan de tous les ports avec détection de version des services
        6 - Ping scan (vérification de l'hôte en ligne)
        7 - Scan XMAS (pour identifier les ports ouverts)
        8 - Scan des 20 ports les plus courants avec détection de version
        """)
        scan_type = input("Entrez le numéro correspondant au type de scan désiré : ")

        capture_traffic_choice = input("Souhaitez-vous effectuer une capture de trafic pour tous les équipements du réseau ? (oui/non) : ").strip().lower()
        capture_traffic_flag = capture_traffic_choice == "oui"

        scan_results = {
            "gateway_ip": gateway_ip,
            "gateway_hostname": gateway_hostname,
            "results": {},
        }

        for host_info in active_hosts_info:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", host_info)
            if ip_match:
                ip = ip_match.group(1)
                host_name = get_hostname_by_ip(ip)
                print(f"Traitement de l'IP active: {ip} ({host_name})")

                nmap_result, versions, cve_results = nmap(ip, intensity, scan_type)

                port_check_result = check_port(ip)
                traffic_capture_file = capture_traffic(ip_address=ip) if capture_traffic_flag else "Non effectué"

                port_status = port_check_result.split("\n")
                for port_info in port_status:
                    if "ouvert" in port_info:
                        port_num = port_info.split(" ")[-1].strip("()").strip(":")
                        if port_num not in versions:
                            versions[port_num] = {"service": "unknown", "version": "unknown"}
                        if port_num not in cve_results:
                            cve_results[port_num] = search_cve("unknown", "unknown")

                scan_results["results"][ip] = {
                    "host_name": host_name,
                    "nmap_result": nmap_result,
                    "port_check_result": port_check_result,
                    "traffic_capture_file": traffic_capture_file,
                    "cve_results": cve_results,
                }

        with open("scan_results.json", "w") as file:
            json.dump(scan_results, file, indent=4)
        print("Résultats du scan enregistrés dans scan_results.json")

    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du scan réseau: {e}")
    except Exception as e:
        print(f"Erreur inattendue lors du scan réseau: {e}")

# Récupère les dernières CVE
def recent_cve(cve_count):
    api_url = f"https://cve.circl.lu/api/last/{cve_count}"
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        cve_entries = response.json()
        for entry in cve_entries:
            print(f"ID : {entry['id']}, Publié le : {entry['Published']}")
            print(f"Résumé : {entry['summary']}\n")
    except requests.exceptions.HTTPError as http_err:
        print(f"Erreur HTTP : {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Erreur de connexion : {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Erreur de timeout : {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Erreur lors de la récupération des données CVE : {req_err}")
    except Exception as e:
        print(f"Erreur inattendue lors de la récupération des données CVE : {e}")

# Vérifie la dureté d'un mot de passe
def verifier_durete_mot_de_passe(mot_de_passe):
    recommandations = []
    valide = True
    if len(mot_de_passe) < 8:
        valide = False
        recommandations.append("Augmentez la longueur du mot de passe à au moins 8 caractères.")
    if not re.search("[a-z]", mot_de_passe):
        valide = False
        recommandations.append("Ajoutez au moins une lettre minuscule.")
    if not re.search("[A-Z]", mot_de_passe):
        valide = False
        recommandations.append("Ajoutez au moins une lettre majuscule.")
    if not re.search("[0-9]", mot_de_passe):
        valide = False
        recommandations.append("Ajoutez au moins un chiffre.")
    if not re.search('[!@#$%^&*(),.?":{}|<>]', mot_de_passe):
        valide = False
        recommandations.append("Ajoutez au moins un caractère spécial (ex. !, @, #, etc.).")
    return valide, recommandations

# Vérifie si un mot de passe a été compromis
def verifier_si_compromis(mot_de_passe):
    sha1pwd = hashlib.sha1(mot_de_passe.encode("utf-8")).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return True, f"Ce mot de passe a été compromis dans des violations de données. Il a été vu {count} fois."
    return False, "Votre mot de passe n'a pas été trouvé dans les violations de données."

# Enregistre le résultat dans un fichier JSON
def enregistrer_resultat_dans_json(fichier, resultat):
    with open(fichier, "w") as fichier_json:
        json.dump(resultat, fichier_json, indent=4, ensure_ascii=False)

# Fonction principale
def main():
    os.system("clear")
    print("\033[1;34m################ Outil de pentest par Maxime Patout pour le projet Toolbox de Nathan Bramli")

    choice = input("\n1. Lancer un scan sur le réseau local\n2. Récupérer les 15 derniers CVEs à jour\n3. Vérification dureté mot de passe + leak dark web\n\n(1, 2, ou 3) : ")
    if choice == "1":
        scan_local_network()
    elif choice == "2":
        recent_cve(15)
    elif choice == "3":
        mot_de_passe = input("Entrez votre mot de passe pour vérification : ")
        valide, recommandations_durete = verifier_durete_mot_de_passe(mot_de_passe)
        compromis, recommandation_compromis = verifier_si_compromis(mot_de_passe)

        resultat = {
            "mot_de_passe_valide": valide,
            "mot_de_passe_compromis": compromis,
            "recommandations_durete": recommandations_durete,
            "recommandation_compromis": recommandation_compromis,
        }

        if valide:
            print("Votre mot de passe respecte les critères de dureté.")
        else:
            print("Votre mot de passe ne respecte pas les critères de dureté. Voir recommandations.")

        if compromis:
            print("Attention : Ce mot de passe a été compromis dans une violation de données.")
        else:
            print("Votre mot de passe n'a pas été trouvé dans les violations de données.")

        enregistrer_resultat_dans_json("resultat_verification_mot_de_passe.json", resultat)
        print("Les résultats et les recommandations ont été enregistrés dans 'resultat_verification_mot_de_passe.json'.")
    else:
        print("Choix invalide. Veuillez sélectionner 1, 2, ou 3.")
    
    try:
        subprocess.run(["python3", "generate_report.py"], check=True)
        print("Rapport généré avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la génération du rapport: {e}")
    except Exception as e:
        print(f"Erreur inattendue lors de la génération du rapport: {e}")

if __name__ == "__main__":
    main()
