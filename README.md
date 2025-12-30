# Analyzer 

##  Description du projet

**Analyzer** est un projet écrit en **Python** dont l’objectif est d’analyser, traiter ou exploiter des données / informations selon des règles définies dans le code.

Ce dépôt est destiné à être **collaboratif** : ce `README.md` sert de guide pour comprendre la structure du projet, son fonctionnement et **comment chaque collègue peut ajouter du code proprement**.

---

##  Technologies utilisées

* **Python 3.10+** (recommandé)
* Librairies Python (voir `requirements.txt` si présent)
* Git & GitHub pour la collaboration

---

##  Prérequis

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

##  Installation du projet

1. **Cloner le dépôt**

   ```bash
   git clone https://github.com/bemazava72002/Analyzer.git
   ```

2. **Accéder au dossier du projet**

   ```bash
   cd Analyzer
   ```

3. **cd venv\Scripts**

   ```bash
   python -m venv venv
   ```
4. **.\activate.bat**
5. **cd ..(jusqu'au repertoire Analzer)**
6. **installation des packages**
   
8. 
4. **Activer l’environnement virtuel**

   * Windows :

     ```bash
     cd venv\Scripts
     ```
     ```bash
     .\activate.bat
     ```
    ```bash
     cd ..(jusqu'au repertoire Analyzer)
     ```
5. **Installer les dépendances** (si `requirements.txt` existe)

   ```bash
   pip install -r requirements.txt
   ```

---

##  Exécution du projet

Selon la structure du projet, exécuter le fichier principal :

```bash
python capture_live.py
```



## Structure du projet

```
Analyzer/

├── capture_live.py       # Point d'entrée du programme
├── requirements.txt      # Dépendances Python
└── README.md             # Documentation du projet
```

**Règle importante** :

* Toute nouvelle fonctionnalité doit être ajoutée dans `src/`
* Les tests doivent être ajoutés dans `tests/`

---

Projet initié par **Julio Bemazava**

---

*Merci de contribuer au projet Analyzer !*

