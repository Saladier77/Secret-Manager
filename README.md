# 🔐 Secrets Manager

Un gestionnaire de secrets local avec interface graphique, entièrement chiffré.
Aucune donnée n'est envoyée sur internet — tout reste sur ton machine.

---

## Fonctionnalités

- Stockage chiffré de mots de passe, tokens API, clés et autres secrets
- Interface graphique moderne (thème sombre)
- Catégories : perso, pro, dev, autre
- Recherche en temps réel
- Copie en un clic dans le presse-papier
- Valeurs masquées par défaut (affichage à la demande)
- Verrouillage de session
- Chiffrement AES-128 via Fernet + dérivation de clé PBKDF2 (500 000 itérations)
- Le texte clair ne touche jamais le disque

---

## Installation

**Prérequis : Python 3.8+**

```bash
# 1. Cloner le repo
git clone https://github.com/TON_USERNAME/secrets-manager.git
cd secrets-manager

# 2. Installer la dépendance
pip install -r requirements.txt

# 3. Lancer
python secrets_manager.py
```

---

## Utilisation

Au premier lancement, crée un **mot de passe maître** (il sera demandé à chaque ouverture).

| Action | Comment |
|---|---|
| Ajouter un secret | Bouton **+ Ajouter** |
| Copier une valeur | Icône 📋 sur la ligne |
| Modifier | Icône ✏️ sur la ligne |
| Supprimer | Icône 🗑 sur la ligne |
| Afficher les valeurs | Bouton **👁 Afficher** |
| Verrouiller | Bouton **🔒 Verrouiller** |

Le vault est sauvegardé dans `~/.secrets_vault.json` (chiffré).

---

## Sécurité

- **Fernet (AES-128-CBC + HMAC-SHA256)** — chiffrement symétrique authentifié
- **PBKDF2HMAC** avec 500 000 itérations et salt aléatoire — ralentit les attaques par force brute
- Le fichier vault est en `chmod 600` (lecture uniquement par le propriétaire)
- Aucune dépendance réseau

---

## Stack technique

- Python 3
- tkinter (interface graphique, inclus dans Python)
- [cryptography](https://cryptography.io) (chiffrement)

---

## Licence

MIT
