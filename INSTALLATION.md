# 🚀 INSTALLATION RAPIDE - 5 MINUTES

## ⚡ Démarrage Ultra-Rapide

### Option 1 : Démarrage Automatique (RECOMMANDÉ)

```bash
# Étape 1 : Aller dans le dossier backend
cd ids_intelligent/backend

# Étape 2 : Lancer le système
python3 start.py
```

✅ **C'EST TOUT !**
- Le script vérifie les dépendances
- Lance le serveur automatiquement
- Ouvre le navigateur sur le dashboard

### Option 2 : Démarrage Manuel

```bash
# Aller dans le dossier backend
cd ids_intelligent/backend

# Lancer directement l'application
python3 app.py
```

Puis ouvrir : **http://localhost:5000**

## 📋 Dépendances Nécessaires

Si les dépendances ne sont pas installées :

```bash
pip install flask flask-cors flask-socketio scapy scikit-learn numpy pandas --break-system-packages
```

OU (avec virtualenv) :

```bash
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors flask-socketio scapy scikit-learn numpy pandas
```

## 🎮 Première Utilisation

1. **Le dashboard s'ouvre automatiquement** dans votre navigateur
2. **Observez les statistiques** qui se mettent à jour en temps réel
3. **Testez les simulations** :
   - Cliquez sur "🔴 Simuler DDoS"
   - Observez les alertes apparaître
   - Regardez les graphiques s'animer

## 🔧 Résolution de Problèmes

### Problème : "Module not found"
**Solution :** Installer les dépendances
```bash
pip install flask flask-cors flask-socketio scikit-learn --break-system-packages
```

### Problème : "Port 5000 already in use"
**Solution :** Changer le port dans `app.py` ligne 280 :
```python
socketio.run(app, host='0.0.0.0', port=8080, ...)
```

### Problème : "Permission denied" pour Scapy
**Solution :** Le système fonctionne en mode simulation (pas besoin de privilèges root)
C'est normal ! La démo utilise du trafic simulé.

### Problème : Le navigateur ne s'ouvre pas
**Solution :** Ouvrir manuellement http://localhost:5000

## 📱 URLs Importantes

- **Dashboard** : http://localhost:5000
- **API Status** : http://localhost:5000/api/status
- **API Stats** : http://localhost:5000/api/stats
- **Liste Alertes** : http://localhost:5000/api/alerts

## 🎯 Test Rapide (30 secondes)

```bash
# Terminal 1 : Lancer le système
cd ids_intelligent/backend
python3 start.py

# Navigateur : http://localhost:5000
# Cliquer sur "🔴 Simuler DDoS"
# Observer les alertes apparaître en temps réel !
```

✅ Si vous voyez des alertes → **ÇA MARCHE !** 🎉

## 📚 Pour Plus d'Infos

- **README.md** : Documentation complète
- **GUIDE_DEMO.md** : Guide de présentation pour l'exposé
- **RECAPITULATIF.md** : Vue d'ensemble du projet

## 💡 Conseils

1. **Laissez tourner quelques minutes** pour voir le système en action
2. **Testez les 3 types de simulation** (DDoS, Port Scan, Malware)
3. **Observez les graphiques** s'animer en temps réel
4. **Vérifiez la console** pour voir les logs de détection

## ✅ Checklist Avant l'Exposé

- [ ] Système testé et fonctionne
- [ ] Les 3 simulations marchent
- [ ] PDF de l'exposé accessible
- [ ] Screenshots du dashboard préparés
- [ ] Guide de démo lu
- [ ] Timing répété (20 min max pour la démo)

**Tu es prêt ! 🚀**
