# 👨‍💻 Michaël Lalancette | Analyste en Cybersécurité


[![LinkedIn](https://img.shields.io/badge/LinkedIn-Profil-blue)](https://www.linkedin.com/in/michael-lalancette/)
[![Email](https://img.shields.io/badge/Email-Contact-red)](mailto:Michael.Lalancette@proton.me)

> ⚠️ Portfolio en construction - projets à venir!



---

## 🎯 Objectif Professionnel

Analyste en cybersécurité spécialisé en détection de menaces et investigation d'incidents.  
Actuellement en formation pour élargir mon expertise vers la sécurité du cloud Azure (SC-900, AZ-500/SC-200), je cherche à contribuer à la protection d'infrastructures cloud et hybrides en combinant surveillance SOC et sécurité cloud.  


---

## 📜 Formations & Certifications

* **AEC Cybersécurité : Protection et Défense** | *Collège Montmorency* | *2023–2024*  
* **TryHackMe - SOC niveau 1** | *[TryHackMe](https://tryhackme.com/dashboard)* | *Octobre 2025*  


**En cours :** 
- **SC-900: Microsoft Security, Compliance, and Identity Fundamentals** | *Microsoft* | *Février 2026*  
- Prochaine étape : **SC-200** (Security Operations Analyst) - **AZ-500** (Azure Security Engineer)




---

## 💼 Compétences

### **Détection & Surveillance**
- Configuration et exploitation de SIEM (Splunk) pour la corrélation de logs multi-sources
- Création de règles de détection (SPL) et d'alertes automatisées
- Déploiement de honeypots et d'infrastructures de détection
- Analyse comportementale et identification d'anomalies

### **Investigation & Forensique**
- Analyse PCAP approfondie et reconstruction de sessions malveillantes
- Extraction d'indicateurs de compromission (IoC)
- Investigation d'e-mails de phishing (en-têtes, liens, pièces jointes)
- Analyse de logs Windows/IIS et corrélation d'événements

### **Réponse aux Incidents**
- Triage d'alertes et priorisation par criticité
- Mapping MITRE ATT&CK des techniques adversaires (TTPs)
- Documentation technique et rédaction de rapports d'incident
- Threat hunting débutant et recherche d'IoC

### **Infrastructure & Outils**
- Administration système (Linux, Windows, Active Directory)
- Virtualisation et environnements isolés (VMware, Docker)
- Sécurité réseau (pfSense, segmentation)
- Automatisation via scripting (Python, Bash, PowerShell)
- Notions de sécurité cloud (AWS)




### **Sécurité Cloud (formation continue)**
- Fondamentaux de sécurité Microsoft Azure
- Principes de sécurité cloud : identité, accès, conformité
- Architecture de sécurité Azure




---

## 💡 Outils 

**Détection & Surveillance**  
Splunk (SIEM) • Suricata (IDS/IPS) • MITRE ATT&CK 

**Analyse & Investigation**  
Wireshark • VirusTotal • AbuseIPDB • Shodan • Cyberchef

**Infrastructure & Systèmes**  
Linux • Windows • Active Directory • VMware • Docker • pfSense • AWS • Azure (en cours)

**Automatisation**  
Python • Bash • PowerShell





---

## 📂 Projets

#### **Analyse d'e-mails de Phishing**  - *Octobre 2025*
[![Statut](https://img.shields.io/badge/Statut-Terminé-green)]()  
👉 **[Documentation complète du projet](https://github.com/Michael-Lalancette/SOC-Phishing)**

* Analyse forensique d'un e-mail de phishing :
   * Analyse des en-têtes (sender IP, SPF/DKIM/DMARC, Received hops)  
   * Vérification de réputation des domaines (VirusTotal, OTX, AbuseIPDB)  
   * Extraction et décodage des liens malveillants  
   * Analyse pièces jointes (hashing - SHA256/MD5)  
   * Cartographie MITRE ATT&CK (TTPs)  
   * Production d'un rapport d'IoCs et recommandations préventives  




---

#### **SOC Lab avec Splunk** - *Septembre 2025*
[![Statut](https://img.shields.io/badge/Statut-Terminé-green)]()  
👉 **[Documentation complète du projet](https://github.com/Michael-Lalancette/SOC-Splunk-Lab)**

* Conception et déploiement d'un SOC miniature dans un environnement virtuel.
   * Mise en place d'un SIEM (Splunk Enterprise) et d'un honeypot IIS avec leurres    
   * Collecte et indexation des logs via Universal Forwarder  
   * Création de règles SPL pour la détection en temps réel  
   * Déclenchement d'alertes automatiques (Triggered Alerts, e-mail via Mailtrap, CSV lookup)  
   * Développement d'un dashboard interactif Splunk pour visualiser les accès au honeypot  
   * Simulation adversaire (reconnaissance → accès → tentative d'exfiltration)
> Validation du pipeline SOC complet (collecte → détection → alerte → triage → visualisation)



---

#### **Analyse de PCAPs avec Wireshark** - *Septembre 2025*
[![Statut](https://img.shields.io/badge/Statut-Terminé-green)]()  
👉 **[Documentation complète du projet](https://github.com/Michael-Lalancette/PCAP-Investigation)**


* Investigation réseau pour la détection d'anomalies et la documentation d'incidents.
   * Identification de trafic suspect et d'activités malveillantes  
   * Corrélation et extraction d'IOCs  
   * Production de rapports techniques d'investigation  




---

## 🚧 Projet en construction


#### **Azure Security Lab** - *2026*
[![Statut](https://img.shields.io/badge/Statut-Planifi%C3%A9-lightgrey)]()

- Déploiement d'une infrastructure Azure sécurisée
- Configuration de Microsoft Defender for Cloud
- Implémentation de politiques de sécurité et conformité
- Intégration avec Microsoft Sentinel (SIEM cloud)


