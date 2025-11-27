#!/bin/bash
# Multi-platform SSH setup (Linux/macOS/Termux)
mkdir -p ~/.ssh && chmod 700 ~/.ssh

# Generate ED25519
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519 -C "valorisa@host" -q

# Generate ED25519-SK (FIDO2)
ssh-keygen -t ed25519-sk -O resident -f ~/.ssh/id_ed25519_sk -C "valorisa@host" -q

# Load keys
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ssh-add ~/.ssh/id_ed25519_sk

# Copy keys to server
read -p "Server user@host: " server
ssh-copy-id -i ~/.ssh/id_ed25519 "$server"
ssh-copy-id -i ~/.ssh/id_ed25519_sk "$server"

# Client config
cat > ~/.ssh/config << 'EOF'
Host server
    HostName server
    User valorisa
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
EOF

echo "Multi-platform SSH setup completed."
