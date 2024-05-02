#!/bin/bash

# Compilation
nasm -f elf64 -o code.o $1

# Vérification des erreurs de compilation
if [ $? -ne 0 ]; then
    echo "Erreur de compilation"
    exit 1
fi

# Édition de liens
ld -o result code.o

# Vérification des erreurs d'édition de liens
if [ $? -ne 0 ]; then
    echo "Erreur d'édition de liens"
    exit 1
fi

# Exécution
./result

# Nettoyage
rm code.o result