# Image de base Python légère
FROM python:3.11-slim

# Répertoire de travail dans le container
WORKDIR /app

# Copie des dépendances en premier (optimise le cache Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du reste du code
COPY . .

# Création du dossier de logs (évite une erreur au démarrage)
RUN mkdir -p logs

# Port exposé par Flask
EXPOSE 5000

# Variables d'environnement Flask
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# Commande de démarrage
CMD ["python", "app.py"]