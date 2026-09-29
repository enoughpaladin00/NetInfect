FROM kathara/base

# Installiamo i prerequisiti per aggiungere il repository di Zeek
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg python3 python3-pip && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y zeek && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Per la pipeline ML, possiamo usare le stesse librerie
RUN pip3 install --no-cache-dir pandas scikit-learn numpy paramiko requests --break-system-packages || pip3 install --no-cache-dir pandas scikit-learn numpy paramiko requests

# Aggiungiamo la directory di zeek al PATH
ENV PATH="/opt/zeek/bin:${PATH}"
