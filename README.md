# 📦 Cyber Security Toolbox 📦

Bienvenue dans **Cyber Security Toolbox**, un projet de pentesting conçu par **Maxime Patout** et développé pour le projet Toolbox de **Nathan Bramli**. Ce projet vous permet de réaliser divers tests de sécurité sur votre réseau local et d'analyser la robustesse de vos mots de passe. 🚀

## 🚀 Fonctionnalités

1. **Scan Réseau Local** 🔍
   - Choix de la carte réseau pour le scan.
   - Identification des hôtes actifs sur le réseau.
   - Choix changement de l'adresse MAC pour le scan. 
   - Scan des services et des ports.
   - Vérification des vulnérabilités (CVE) pour chaque hôte scanné.
   - Capture de trafic réseau.

3. **Vérification des CVEs Récentes** 🛡️
   - Récupération des 15 derniers CVEs publiées.

4. **Analyse des Mots de Passe** 🔐
   - Vérification de la robustesse des mots de passe.
   - Vérification si le mot de passe a été compromis.

## 📂 Structure du Projet

- `script_patout.py` : Script principal pour exécuter les différentes fonctionnalités.
- `generate_report.py` : Script pour générer un rapport HTML basé sur les résultats des scans et des analyses.

## 🚀 Utilisation

### Prérequis
- Python 3
- `requests` module
- `psutil` module

### Installation

Clonez le dépôt GitHub :
```sh
git clone hhttps://github.com/maximep78/Cyber-Security-Toolbox.git
cd Cyber-Security-Toolbox
```

Installez les dépendances nécessaires :
```sh
pip install -r requirements.txt
```

**Exécution**

Lancez le script principal :
```sh
sudo python3 script_patout.py
```

**Exemple de Fonctionnalité**
```sh
Souhaitez-vous echanger d'adresse MAC ? (oui/non) : oui
Choisissez l'intensité du scan (1: Faible, 2: Moyen, 3: Élevé) : 2
Choisissez le type de scan (1-8) : 3
Souhaitez-vous effectuer une capture de trafic ? (oui/non) : oui
```

## 📊 Rapport
Un rapport HTML détaillé est généré après chaque exécution et inclut :

  - Conformité des mots de passe 🔐
  - Résultats des scans réseau 🌐
  - Analyse des vulnérabilités (CVE) 🛡️

Le rapport peut être converti en PDF directement via l'interface HTML.

## 📄 License

Ce projet est sous licence MIT License.
