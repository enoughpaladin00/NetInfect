#!/bin/bash
# stop.sh - Ferma i processi di Kathara

echo "🛑 Spegnimento dell'infrastruttura di Kathara in corso..."
cd lab && kathara lclean

echo "✅ Fatto! Puoi chiudere tranquillamente le 4 finestre del terminale."
