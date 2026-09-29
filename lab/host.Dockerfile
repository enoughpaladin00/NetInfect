FROM kathara/base

# Aggiorniamo e installiamo Python3 e pip
RUN apt-get update && \
    apt-get install -y python3 python3-pip curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Installiamo solo le librerie per la generazione del traffico (evitiamo Pandas/Scikit qui per non appesantire)
# Utilizziamo --break-system-packages nel caso le versioni recenti di Debian/Ubuntu nel base image lo richiedano
RUN pip3 install --no-cache-dir requests paramiko --break-system-packages || pip3 install --no-cache-dir requests paramiko
