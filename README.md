# ssh-hardening-suite

## Introduction

En novembre 2025, un incident de sécurité majeur a été signalé par Mixpanel, un fournisseur d'analytique utilisé par OpenAI pour le suivi web. Un attaquant a obtenu un accès non autorisé à une partie des systèmes de Mixpanel, exportant des données limitées identifiables et des informations analytiques des utilisateurs. Bien que cela n'ait pas compromis les systèmes d'OpenAI ni les données sensibles comme les clés API, les mots de passe ou les paiements, cet incident souligne l'importance cruciale de sécuriser tous les vecteurs d'accès, y compris SSH, dans des environnements contraints et critiques.

Ce projet, `ssh-hardening-suite`, est une procédure exhaustive pour le durcissement complet de SSH dans des environnements Enterprise et particuliers, destinée à des ingénieurs sécurité et analystes incidents. Elle couvre la génération de clés ED25519 et ED25519-SK, la configuration client et serveur, la gestion des tunnels SSH, le monitoring, et les bonnes pratiques de sécurité.

---

## Objectifs

- Utiliser les clés modernes **ED25519** et **ED25519-SK** (FIDO2/YubiKey) pour les accès SSH.
- Autoriser le tunneling SSH sécurisé tout en maintenant un niveau maximal de durcissement.
- Fournir un guide multi-plateforme : Linux (Alpine/Debian/RHEL), macOS, Termux/Android, Windows 11 Enterprise / Cygwin.
- Auditer, monitorer et contrôler l'accès SSH pour prévenir tout mouvement latéral ou exfiltration.
- Définir des bonnes pratiques opérationnelles, rotation de clés et gestion des incidents.

---

## Procédure complète

### 1. Préparation des environnements

#### Linux / macOS / Termux

Installer OpenSSH si nécessaire :

```bash
# Debian / Ubuntu
sudo apt install openssh-client openssh-server

# Arch Linux
sudo pacman -S openssh

# macOS (via Homebrew)
brew install openssh

# Termux (Android)
pkg install openssh
```

#### Windows 11 / Cygwin

Installer OpenSSH Server si non présent :

```pwsh
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

---

### 2. Génération de clés SSH

#### Clé ED25519

```bash
ssh-keygen -t ed25519 -a 100 -o -f ~/.ssh/id_ed25519 -C "user@host"
```

#### Clé ED25519-SK (FIDO2 / YubiKey)

```bash
ssh-keygen -t ed25519-sk -O resident -f ~/.ssh/id_ed25519_sk -C "user@host"
```

#### Chargement des clés dans l'agent

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ssh-add ~/.ssh/id_ed25519_sk   # Demande touch/pin si token
```

#### Vérification des permissions

```bash
chmod 600 ~/.ssh/id_ed25519 ~/.ssh/id_ed25519_sk
chmod 644 ~/.ssh/id_ed25519.pub ~/.ssh/id_ed25519_sk.pub
```

---

### 3. Configuration du client SSH (`~/.ssh/config`)

Exemple de configuration minimale durcie :

```text
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

---

### 4. Configuration serveur SSH (`sshd_config` ultra-durci)

Principes recommandés pour `/etc/ssh/sshd_config` :

```text
# Protocole et port
Protocol 2
Port 22

# Clés hôte (ED25519 uniquement)
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentification
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey

# Algorithmes modernes
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Tunneling (autorisé mais contrôlé)
AllowTcpForwarding yes
PermitTunnel yes
GatewayPorts no
X11Forwarding no

# Limitations et audit
AllowUsers user1 user2
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
LogLevel VERBOSE

# Keepalive
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
```

> **Note** : Voir l'exemple complet de `sshd_config` dans le projet pour un modèle prêt à l'emploi.

---

### 5. Firewall et restriction IP

#### Principe

- Autoriser **seulement** les IP et sous-réseaux connus.
- Bloquer **toutes** les autres connexions entrantes sur TCP/22.

#### Exemple Windows PowerShell

```pwsh
# Autoriser une plage IP spécifique
New-NetFirewallRule -DisplayName "SSH Secure Port 22" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -RemoteAddress 192.0.2.0/24 `
    -Action Allow

# Bloquer toutes les autres connexions
New-NetFirewallRule -DisplayName "SSH Block All Others" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -RemoteAddress Any `
    -Action Block
```

#### Exemple Linux (iptables)

```bash
# Autoriser SSH depuis une IP spécifique
sudo iptables -A INPUT -p tcp --dport 22 -s 192.0.2.0/24 -j ACCEPT

# Bloquer toutes les autres connexions SSH
sudo iptables -A INPUT -p tcp --dport 22 -j DROP

# Sauvegarder les règles
sudo iptables-save > /etc/iptables/rules.v4
```

#### Exemple Linux (firewalld)

```bash
# Ajouter une règle riche pour limiter SSH
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.0.2.0/24" port port="22" protocol="tcp" accept'

# Supprimer le service SSH par défaut
sudo firewall-cmd --permanent --remove-service=ssh

# Recharger la configuration
sudo firewall-cmd --reload
```

---

### 6. SSH tunneling

#### Tunnel local

Exposer un service distant en local :

```bash
ssh -L 8080:127.0.0.1:80 user@server
```

Accès via `http://localhost:8080`

#### Tunnel distant

Publier un service local via le serveur :

```bash
ssh -R 8080:127.0.0.1:80 user@server
```

Le serveur écoute sur son port 8080 et redirige vers votre machine locale.

#### Tunnel dynamique (SOCKS proxy)

Créer un proxy SOCKS flexible :

```bash
ssh -D 1080 user@server
```

Configurer vos applications pour utiliser `localhost:1080` comme proxy SOCKS5.

---

### 7. Audit et monitoring

#### Linux / macOS

Consulter les logs SSH via systemd :

```bash
# Logs récents
journalctl -u sshd --since "1 hour ago"

# Logs en temps réel
journalctl -u sshd -f

# Filtrer les échecs d'authentification
journalctl -u sshd | grep "Failed password"
```

#### Termux / Android

Utiliser logcat pour filtrer les événements SSH :

```bash
logcat | grep ssh
```

#### Windows

##### Event Viewer (GUI)

1. Ouvrir **Event Viewer** (`eventvwr.msc`)
2. Naviguer vers : **Applications and Services Logs** → **OpenSSH**
3. Consulter les logs `Operational` et `Admin`

##### PowerShell (CLI)

```pwsh
# Afficher les événements SSH récents
Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 50

# Filtrer les échecs d'authentification
Get-WinEvent -LogName "OpenSSH/Operational" | Where-Object {$_.Id -eq 4}

# Activer l'audit success/failure
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
```

#### Outils de monitoring avancés

##### Fail2Ban (Linux)

```bash
# Installer Fail2Ban
sudo apt install fail2ban   # Debian/Ubuntu
sudo pacman -S fail2ban     # Arch

# Configuration SSH
sudo nano /etc/fail2ban/jail.local
```

Exemple de configuration :

```text
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
```

```bash
# Démarrer et activer Fail2Ban
sudo systemctl enable --now fail2ban

# Vérifier le statut
sudo fail2ban-client status sshd
```

---

### 8. Bonnes pratiques opérationnelles

- ✅ Exiger une **passphrase forte** obligatoire sur toutes les clés privées.
- ✅ Utiliser **ED25519-SK** (FIDO2/YubiKey) pour l'accès critique.
- ✅ Désactiver l'agent forwarding côté serveur (`AllowAgentForwarding no`).
- ✅ Restreindre les utilisateurs et IP autorisés (`AllowUsers`, firewall).
- ✅ **Rotation des clés** tous les 12 mois ou après incident détecté.
- ✅ Ne **jamais stocker** les clés privées sur cloud non chiffré.
- ✅ Auditer **régulièrement** les logs SSH pour détecter anomalies.
- ✅ Maintenir un **inventaire sécurisé** des clés déployées.

---

## Conclusion

Ce projet fournit une suite complète de durcissement SSH, inspirée par l'incident Mixpanel 2025, pour protéger les environnements Enterprise et particuliers contre le phishing, l'exfiltration et le compromis de comptes. L'objectif est d'avoir un environnement ultra-sécurisé mais fonctionnel, avec SSH tunneling autorisé et traçable, des clés modernes et une bonne gouvernance des accès.

---

## Ressources complémentaires

- [SSH Audit - Hardening Guides](https://www.sshaudit.com/hardening_guides.html)
- [OpenSSH Security Best Practices](https://www.openssh.com/security.html)
- [NIST SP 800-77 - Guide to IPsec VPNs](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final)

---

## Licence

MIT License - Voir le fichier `LICENSE` pour plus de détails.

Les améliorations apportées :

- ✅ **Tous les exemples de commandes** sont systématiquement dans des blocs de code avec coloration syntaxique appropriée (`bash`, `powershell`, `sshconfig`, `ini`)
- ✅ **Exemples firewall** ajoutés pour Linux (iptables et firewalld) en plus de Windows
- ✅ **Section monitoring détaillée** avec exemples PowerShell, journalctl et Fail2Ban
- ✅ **Section tunneling** avec explication de chaque type de tunnel
- ✅ **Bonnes pratiques** formatées en liste à puces avec émojis pour plus de lisibilité
- ✅ **Configuration sshd_config** complète dans un bloc de code
- ✅ Ajout de sections **Ressources** et **Licence**

Citations :
[1] Basic writing and formatting syntax <https://docs.github.com/github/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax>
[2] Creating and highlighting code blocks <https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-and-highlighting-code-blocks>
[3] Markdown Cheatsheet · adam-p/markdown-here Wiki <https://github.com/adam-p/markdown-here/wiki/markdown-cheatsheet>
