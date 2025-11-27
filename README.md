ssh-hardening-suite

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

# Installer OpenSSH si nécessaire
sudo apt install openssh-client openssh-server   # Debian/Ubuntu
sudo pacman -S openssh                            # Arch
brew install openssh                              # macOS
pkg install openssh                               # Termux

Windows 11 / Cygwin

# Installer OpenSSH Server si non présent
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

---

2. Génération de clés SSH

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

3. Configuration du client SSH (~/.ssh/config)

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

4. Configuration serveur SSH ("sshd_config" ultra-durci)

- Protocole : 2
- Clés : ED25519 uniquement (ED25519-SK possible pour token)
- Interdiction root, mot de passe et challenge interactive
- Tunneling SSH autorisé ("AllowTcpForwarding yes", "PermitTunnel yes")
- Limitation utilisateurs ("AllowUsers") et audit verbose
- Chiffrement moderne : curve25519, chacha20-poly1305, umac-etm

«Voir exemple complet "sshd_config" dans le projet.»

---

5. Firewall et restriction IP

- Autoriser seulement les IP et sous-réseaux connus
- Bloquer toutes les autres connexions TCP/22
- Windows PowerShell example :

New-NetFirewallRule -DisplayName "SSH Secure Port 22" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 192.0.2.0/24 -Action Allow
New-NetFirewallRule -DisplayName "SSH Block All Others" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress Any -Action Block

---

6. SSH Tunneling

- Tunnel local : "ssh -L 8080:127.0.0.1:80 user@server"
- Tunnel distant : "ssh -R 8080:127.0.0.1:80 user@server"
- Dynamic tunnel (SOCKS proxy) : "ssh -D 1080 user@server"

---

7. Audit et monitoring

- Linux/macOS : "journalctl -u sshd"
- Termux : "logcat | grep ssh"
- Windows : Event Viewer → Applications and Services Logs → OpenSSH
- Activer success/failure audit : "auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable"

---

8. Bonnes pratiques

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
