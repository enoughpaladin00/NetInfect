FROM kathara/base

# Installiamo Zeek e Python (servirà per la pipeline ML e l'Active Response)
# DEBIAN_FRONTEND=noninteractive evita che l'installazione si blocchi chiedendo configurazioni per la mail
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y zeek python3 python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Per la pipeline ML, possiamo usare le stesse librerie
RUN pip3 install --no-cache-dir pandas scikit-learn numpy paramiko requests --break-system-packages || pip3 install --no-cache-dir pandas scikit-learn numpy paramiko requests

# Aggiungiamo la directory di zeek al PATH
ENV PATH="/opt/zeek/bin:${PATH}"
