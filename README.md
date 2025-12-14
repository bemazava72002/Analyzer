# Analyzer 🧠🐍

## 📌 Description du projet

**Analyzer** est un projet écrit en **Python** dont l’objectif est d’analyser, traiter ou exploiter des données / informations selon des règles définies dans le code.

Ce dépôt est destiné à être **collaboratif** : ce `README.md` sert de guide pour comprendre la structure du projet, son fonctionnement et **comment chaque collègue peut ajouter du code proprement**.

---

## 🛠️ Technologies utilisées

* **Python 3.10+** (recommandé)
* Librairies Python (voir `requirements.txt` si présent)
* Git & GitHub pour la collaboration

---

## ⚙️ Prérequis

Avant de commencer, assure-toi d’avoir installé :

* Python :

  ```bash
  python --version
  ```
* pip :

  ```bash
  pip --version
  ```
* Git :

  ```bash
  git --version
  ```

---

## 🚀 Installation du projet

1. **Cloner le dépôt**

   ```bash
   git clone https://github.com/bemazava72002/Analyzer.git
   ```

2. **Accéder au dossier du projet**

   ```bash
   cd Analyzer
   ```

3. **Créer un environnement virtuel (recommandé)**

   ```bash
   python -m venv venv
   ```

4. **Activer l’environnement virtuel**

   * Windows :

     ```bash
     venv\Scripts\activate
     ```
   * Linux / macOS :

     ```bash
     source venv/bin/activate
     ```

5. **Installer les dépendances** (si `requirements.txt` existe)

   ```bash
   pip install -r requirements.txt
   ```

---

## ▶️ Exécution du projet

Selon la structure du projet, exécuter le fichier principal :

```bash
python main.py
```

ou

```bash
python app.py
```

*(Adapter selon le vrai point d’entrée du projet)*

---

## 🧠 Structure du projet

```
Analyzer/
├── src/                  # Code source principal
│   ├── __init__.py
│   ├── analyzer.py       # Logique principale d’analyse
│   ├── utils.py          # Fonctions utilitaires
│   └── ...
├── tests/                # Tests unitaires
├── requirements.txt      # Dépendances Python
├── main.py               # Point d’entrée du programme
└── README.md             # Documentation du projet
```

👉 **Règle importante** :

* Toute nouvelle fonctionnalité doit être ajoutée dans `src/`
* Les tests doivent être ajoutés dans `tests/`

---

## 🧩 Comment ajouter du code (important pour l’équipe)

### 1️⃣ Créer une nouvelle branche

⚠️ Ne jamais coder directement sur `main`

```bash
git checkout -b feature/nom-de-la-feature
```

Exemples :

* `feature/analyse-fichier`
* `feature/optimisation-algo`

---

### 2️⃣ Règles de codage Python

Merci de respecter les bonnes pratiques suivantes :

* Respecter la **PEP8** (indentation, noms clairs)
* Fonctions courtes et lisibles
* Ajouter des **docstrings**

Exemple :

```python
def analyze_data(data: list) -> dict:
    """
    Analyse une liste de données et retourne un résumé.
    """
    return {
        "count": len(data)
    }
```

---

### 3️⃣ Ajouter des tests (si possible)

Chaque nouvelle fonctionnalité importante doit avoir un test associé dans le dossier `tests/`.

---

### 4️⃣ Faire une Pull Request (PR)

1. Commit ton code :

   ```bash
   git add .
   git commit -m "Ajout de la fonctionnalité X"
   ```
2. Push la branche :

   ```bash
   git push origin feature/nom-de-la-feature
   ```
3. Ouvre une **Pull Request** sur GitHub
4. Explique clairement ce que fait ton code

---

## 🧪 Tests

Pour lancer les tests (si `pytest` est utilisé) :

```bash
pytest
```

---

## 🤝 Règles de collaboration

✔ Une feature = une branche
✔ Code lisible et commenté
✔ Pas de code cassé sur `main`
✔ Communication claire dans les PR

---

## 📄 Licence

Ce projet est sous licence **MIT** (ou autre si précisé).

---

## ✨ Auteur

Projet initié par **Julio Bemazava**

---

🚀 *Merci de contribuer au projet Analyzer !*

