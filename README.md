# ssh-hardening-suite

Introduction

En novembre 2025, un incident de sécurité majeur a été signalé par Mixpanel, un fournisseur d'analytique utilisé par OpenAI pour le suivi web. Un attaquant a obtenu un accès non autorisé à une partie des systèmes de Mixpanel, exportant des données limitées identifiables et des informations analytiques des utilisateurs. Bien que cela n'ait pas compromis les systèmes d'OpenAI ni les données sensibles comme les clés API, les mots de passe ou les paiements, cet incident souligne l'importance cruciale de sécuriser tous les vecteurs d'accès, y compris SSH, dans des environnements contraints et critiques.

Ce projet, ssh-hardening-suite, est une procédure exhaustive pour le durcissement complet de SSH dans des environnements Enterprise et particuliers, destinée à des ingénieurs sécurité et analystes incidents. Elle couvre la génération de clés ED25519 et ED25519-SK, la configuration client et serveur, la gestion des tunnels SSH, le monitoring, et les bonnes pratiques de sécurité.

---

Objectifs

- Utiliser les clés modernes ED25519 et ED25519-SK (FIDO2/YubiKey) pour les accès SSH.
- Autoriser le tunneling SSH sécurisé tout en maintenant un niveau maximal de durcissement.
- Fournir un guide multi-plateforme : Linux (Alpine/Debian/RHEL), macOS, Termux/Android, Windows 11 Enterprise / Cygwin.
- Auditer, monitorer et contrôler l'accès SSH pour prévenir tout mouvement latéral ou exfiltration.
- Définir des bonnes pratiques opérationnelles, rotation de clés et gestion des incidents.

---

Procédure complète

1. Préparation des environnements

Linux/macOS/Termux

## Installer OpenSSH si nécessaire

sudo apt install openssh-client openssh-server   # Debian/Ubuntu
sudo pacman -S openssh                            # Arch
brew install openssh                              # macOS
pkg install openssh                               # Termux

Windows 11 / Cygwin

## Installer OpenSSH Server si non présent

Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

---

1. Génération de clés SSH

Clé ED25519

ssh-keygen -t ed25519 -a 100 -o -f ~/.ssh/id_ed25519 -C "user@host"

Clé ED25519-SK (FIDO2 / YubiKey)

ssh-keygen -t ed25519-sk -O resident -f ~/.ssh/id_ed25519_sk -C "user@host"

Chargement des clés dans l'agent

eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ssh-add ~/.ssh/id_ed25519_sk  # Demande touch/pin si token

Vérification des permissions

chmod 600 ~/.ssh/id_ed25519 ~/.ssh/id_ed25519_sk
chmod 644 ~/.ssh/id_ed25519.pub ~/.ssh/id_ed25519_sk.pub

---

1. Configuration du client SSH (~/.ssh/config)

Host server.example.com
    HostName server.example.com
    User user
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PubkeyAcceptedAlgorithms +ssh-ed25519
    HostKeyAlgorithms +ssh-ed25519
    Compression no
    ForwardAgent no
    ServerAliveInterval 120
    ServerAliveCountMax 2
    TCPKeepAlive no
    PermitLocalCommand yes

---

1. Configuration serveur SSH ("sshd_config" ultra-durci)

- Protocole : 2
- Clés : ED25519 uniquement (ED25519-SK possible pour token)
- Interdiction root, mot de passe et challenge interactive
- Tunneling SSH autorisé ("AllowTcpForwarding yes", "PermitTunnel yes")
- Limitation utilisateurs ("AllowUsers") et audit verbose
- Chiffrement moderne : curve25519, chacha20-poly1305, umac-etm

«Voir exemple complet "sshd_config" dans le projet.»

---

1. Firewall et restriction IP

- Autoriser seulement les IP et sous-réseaux connus
- Bloquer toutes les autres connexions TCP/22
- Windows PowerShell example :

New-NetFirewallRule -DisplayName "SSH Secure Port 22" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 192.0.2.0/24 -Action Allow
New-NetFirewallRule -DisplayName "SSH Block All Others" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress Any -Action Block

---

1. SSH Tunneling

- Tunnel local : "ssh -L 8080:127.0.0.1:80 user@server"
- Tunnel distant : "ssh -R 8080:127.0.0.1:80 user@server"
- Dynamic tunnel (SOCKS proxy) : "ssh -D 1080 user@server"

---

1. Audit et monitoring

- Linux/macOS : "journalctl -u sshd"
- Termux : "logcat | grep ssh"
- Windows : Event Viewer → Applications and Services Logs → OpenSSH
- Activer success/failure audit : "auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable"

---

1. Bonnes pratiques

- Passphrase forte obligatoire sur toutes les clés privées
- Utiliser ED25519-SK pour l’accès critique (FIDO2)
- Désactiver agent forwarding côté serveur
- Restreindre les utilisateurs et IP autorisés
- Rotation des clés tous les 12 mois ou après incident
- Ne jamais stocker les clés privées sur cloud non chiffré
- Auditer régulièrement les logs pour détecter mouvement latéral ou anomalies
- Limiter la distribution de clés et maintenir un inventaire sécurisé

---

Conclusion

Ce projet fournit une suite complète de durcissement SSH, inspirée par l’incident Mixpanel 2025, pour protéger les environnements Enterprise et particuliers contre le phishing, l’exfiltration et le compromis de comptes. L’objectif est d’avoir un environnement ultra-sécurisé mais fonctionnel, avec SSH tunneling autorisé et traçable, des clés modernes et une bonne gouvernance des accès.

---

# ssh-hardening-suite

Une suite de procédures pour durcir SSH de bout en bout dans des environnements Enterprise et particuliers, avec un focus sur les clés modernes, le tunneling contrôlé et l’audit de la surface d’attaque SSH.[1]

## Contexte

En novembre 2025, Mixpanel a subi un incident de sécurité permettant à un attaquant d’exporter un jeu de données contenant des informations analytiques et des données identifiables d’utilisateurs d’API OpenAI, sans compromettre les systèmes d’OpenAI ni les secrets tels que clés API, mots de passe ou paiements.[2][3][4] Cet événement illustre l’importance de maîtriser tous les vecteurs d’accès, dont SSH, pour réduire les risques de mouvement latéral, de phishing ciblé et d’exfiltration de données.[3][5]

## Objectifs du projet

- Utiliser des clés modernes ED25519 et ED25519-SK (FIDO2/YubiKey) comme standard pour l’authentification SSH.[6][7]
- Autoriser un tunneling SSH (local, distant, dynamique) sécurisé et traçable, sans affaiblir le niveau de durcissement global.[1]
- Fournir un guide multi-plateforme : Linux (Alpine/Debian/RHEL), macOS, Termux/Android, Windows 11 Enterprise / Cygwin.  
- Auditer, monitorer et contrôler précisément l’accès SSH pour limiter le mouvement latéral et détecter les anomalies précocement.[8][9]
- Définir des bonnes pratiques opérationnelles : rotation de clés, gestion d’incidents, limitation d’IP et journalisation renforcée.[1][10]

***

## 1. Préparation des environnements

### Linux / macOS / Termux

Installer OpenSSH si nécessaire (adapté à la distribution) :

```bash
# Debian / Ubuntu
sudo apt install openssh-client openssh-server

# Arch Linux
sudo pacman -S openssh

# macOS (Homebrew)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install openssh

# Termux (Android)
pkg update
pkg install openssh
```

Ces commandes assurent la présence du client et du serveur OpenSSH sur les systèmes Unix-like supportés.[1][11]

### Windows 11 / Cygwin

Sur Windows 11 Enterprise, activer et démarrer le serveur OpenSSH intégré :

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

Cette configuration permet de disposer d’un service sshd persistant, géré via les outils d’administration Windows classiques.[12]

***

## 2. Génération de clés SSH

### Clé ED25519 (recommandée)

```bash
ssh-keygen -t ed25519 -a 100 -o -f ~/.ssh/id_ed25519 -C "user@host"
```

Les clés ED25519 offrent d’excellentes propriétés de sécurité, des performances élevées et un format moderne conseillé par de nombreux guides de durcissement SSH.[1][7]

### Clé ED25519-SK (FIDO2 / YubiKey)

```bash
ssh-keygen -t ed25519-sk -O resident -f ~/.ssh/id_ed25519_sk -C "user@host"
```

Les clés ED25519-SK utilisent un token matériel (FIDO2/YubiKey) et ajoutent une authentification liée au dispositif physique, particulièrement adaptée aux accès critiques.[6][7]

### Chargement des clés dans l’agent

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ssh-add ~/.ssh/id_ed25519_sk   # Demande un touch/PIN si token
```

L’agent SSH gère les clés en mémoire et permet de limiter l’exposition des clés sur disque durant les sessions actives.[6][7]

### Vérification des permissions

```bash
chmod 600 ~/.ssh/id_ed25519 ~/.ssh/id_ed25519_sk
chmod 644 ~/.ssh/id_ed25519.pub ~/.ssh/id_ed25519_sk.pub
```

Des permissions strictes sur les fichiers de clés réduisent les risques de compromission locale et sont un prérequis pour un durcissement efficace.[7][12]

***

## 3. Configuration du client SSH

Créer ou éditer le fichier `~/.ssh/config` pour définir une configuration stricte par hôte :

```sshconfig
Host server.example.com
    HostName server.example.com
    User user
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PubkeyAcceptedAlgorithms +ssh-ed25519
    HostKeyAlgorithms +ssh-ed25519
    Compression no
    ForwardAgent no
    ServerAliveInterval 120
    ServerAliveCountMax 2
    TCPKeepAlive no
    PermitLocalCommand yes
```

Ce profil client force l’usage de la clé ED25519, désactive l’agent forwarding, et réduit la surface d’attaque en limitant les algorithmes et les options superflues.[1][11]

***

## 4. Configuration serveur ultra-durcie

La configuration serveur (`/etc/ssh/sshd_config` ou équivalent) suit les principes suivants :

- Protocole SSH 2 uniquement, avec des clés de type ED25519 comme standard et ED25519-SK pour les tokens matériels.[1][11]
- Désactivation de l’accès root direct, des mots de passe et des authentifications interactives (challenge-response).[1][12]
- Tunneling SSH autorisé et contrôlé (`AllowTcpForwarding yes`, `PermitTunnel yes`) pour permettre les usages légitimes tout en journalisant les accès.[1]
- Limitation des comptes via `AllowUsers` et augmentation du niveau de verbosité des logs pour l’audit.[1][13]
- Sélection d’algorithmes modernes (curve25519, chacha20-poly1305, MACs *etm* et ciphers récents) afin d’éviter les suites obsolètes.[1][11]

Voir l’exemple complet de `sshd_config` fourni dans le projet pour un modèle prêt à l’emploi.[1]

***

## 5. Firewall et restrictions IP

Appliquer un filtrage réseau strict pour le port SSH (TCP/22) :

- Autoriser uniquement les adresses IP et sous-réseaux explicitement approuvés pour le service SSH.[10]
- Bloquer toutes les autres tentatives de connexion entrantes sur le port 22, côté pare-feu système ou périmétrique.[10]

Exemple en Windows PowerShell :

```powershell
New-NetFirewallRule -DisplayName "SSH Secure Port 22" `
    -Direction Inbound -Protocol TCP -LocalPort 22 `
    -RemoteAddress 192.0.2.0/24 -Action Allow

New-NetFirewallRule -DisplayName "SSH Block All Others" `
    -Direction Inbound -Protocol TCP -LocalPort 22 `
    -RemoteAddress Any -Action Block
```

Cette approche limite l’exposition du service sshd à des plages IP connues et réduit la surface d’attaque globale.[10][12]

***

## 6. SSH tunneling (contrôlé)

Les tunnels SSH sont autorisés mais doivent être utilisés dans un cadre maîtrisé :

- Tunnel local : `ssh -L 8080:127.0.0.1:80 user@server` pour exposer un service distant en local.[1]
- Tunnel distant : `ssh -R 8080:127.0.0.1:80 user@server` pour publier un service local via le serveur.[1]
- Tunnel dynamique (SOCKS proxy) : `ssh -D 1080 user@server` pour un proxy SOCKS flexible.[1]

Le durcissement côté serveur garantit que ces tunnels restent traçables et intégrés à la stratégie de logging.[8][13]

***

## 7. Audit et monitoring

Mettre en place un suivi continu des événements SSH sur chaque plateforme :

- Linux / macOS (systemd) :  
  - `journalctl -u sshd` ou `journalctl -u ssh --since "1 hour ago"` pour les logs récents.[8][9]
- Termux / Android :  
  - `logcat | grep ssh` pour filtrer les événements liés au serveur ou client SSH.[8]  
- Windows :  
  - Observateur d’événements → Applications and Services Logs → OpenSSH.[12]
  - Renforcer l’audit :  
    ```powershell
    auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
    ```

L’activation d’un audit détaillé, combinée à des outils d’analyse centralisée, facilite la détection de comportements anormaux et la réponse aux incidents.[8][13]

***

## 8. Bonnes pratiques opérationnelles

- Exiger une passphrase robuste pour toutes les clés privées, en complément d’un stockage chiffré des systèmes.[7][12]
- Utiliser ED25519-SK (FIDO2/YubiKey) pour les comptes particulièrement sensibles ou dotés de privilèges élevés.[6][7]
- Désactiver l’agent forwarding côté serveur et limiter les sauts de rebond non maîtrisés.[1]
- Restreindre les utilisateurs autorisés et leurs IP, et maintenir un inventaire précis des clés déployées.[1][10]
- Mettre en place une rotation régulière des clés (par exemple tous les 12 mois ou après incident détecté).[6][7]
- Ne jamais stocker de clés privées sur des services cloud non chiffrés ou des dossiers partagés non maîtrisés.[7][12]
- Auditer fréquemment les logs SSH pour identifier toute tentative de mouvement latéral ou d’accès suspect.[8][13]

***

## 9. Récapitulatif

Ce projet propose une procédure complète de durcissement SSH inspirée notamment par l’incident Mixpanel 2025, afin de mieux protéger les environnements Enterprise et particuliers contre le phishing ciblé, l’exfiltration et la compromission de comptes.[2][3] L’objectif est d’obtenir un environnement SSH ultra-sécurisé mais fonctionnel, avec un tunneling autorisé et journalisé, des clés modernes et une gouvernance rigoureuse des accès et des incidents.[1][8]

Citations :
[1] SSH Hardening Guides https://www.sshaudit.com/hardening_guides.html
[2] What to know about a recent Mixpanel security incident https://openai.com/index/mixpanel-incident/
[3] Mixpanel Incident Exposes Limited API User Data https://www.bitdefender.com/en-us/blog/hotforsecurity/openai-breach-alert-mixpanel-incident-exposes-limited-api-user-data
[4] OpenAI reveals analytics data breach, notifies affected users https://cybernews.com/security/openai-mixpanel-cybersecurity-incident-breach/
[5] Mixpanel piraté par SMS : l'alerte qui a fait trembler les ... https://www.thesiteoueb.net/actualite/article-9329-mixpanel-pirate-par-sms-l-alerte-qui-a-fait-trembler-les-utilisateurs-d-openai.html
[6] SSH Key Best Practices for 2025 - Using ed25519, key rotation, and ... https://www.brandonchecketts.com/archives/ssh-ed25519-key-best-practices-for-2025
[7] How to secure your SSH server with public key Ed25519 elliptic ... https://cryptsus.com/blog/how-to-secure-your-ssh-server-with-public-key-elliptic-curve-ed25519-crypto.html
[8] SSH Logs: Complete Guide to Security Monitoring and ... https://signoz.io/guides/ssh-logs/
[9] Mastering SSH Logs: A Comprehensive Guide https://betterstack.com/community/guides/logging/ssh-logging/
[10] Linux Security Logs: Complete Guide for DevOps and ... https://last9.io/blog/linux-security-logs/
[11] IT Log :: OpenSSH : Harden the service - Stéphane HUC https://doc.huc.fr.eu.org/en/sec/ssh/sshd-harden/
[12] Securing network operations with OpenSSH | SLES 15 SP7 https://documentation.suse.com/sles/15-SP7/html/SLES-all/cha-ssh.html
[13] SSH Audit Logging: Tracking User Activity on Your Server https://dohost.us/index.php/2025/09/14/ssh-audit-logging-tracking-user-activity-on-your-server/
[14] Data breach at OpenAI through analytics provider Mixpanel ... https://securitybrief.com.au/story/data-breach-at-openai-through-analytics-provider-mixpanel-platform
[15] OpenAI confirms major data breach, exposing names ... https://www.windowscentral.com/artificial-intelligence/openai-chatgpt/openai-confirms-major-data-breach-exposing-users-names-email-addresses-and-more-transparency-is-important-to-us
[16] OpenAI Notifies Users of Mixpanel Security Incident https://socradar.io/openai-notifies-users-mixpanel-security-incident/
[17] OpenSSH 9.6p1: What is the best key type for the ssh-keygen ... https://itsfoss.community/t/openssh-9-6p1-what-is-the-best-key-type-for-the-ssh-keygen-command-through-the-t-option/12276
[18] Mixpanel Security Breach https://news.ycombinator.com/item?id=46066522
[19] OpenAI says hackers stole data from its analytics partner https://www.businessinsider.com/openai-mixpanel-hackers-stole-data-analytics-partner-chatgpt-2025-11
[20] Best practices for auditing SSH access | Compute Engine https://docs.cloud.google.com/compute/docs/connect/ssh-best-practices/auditing
