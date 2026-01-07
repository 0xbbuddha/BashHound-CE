# Limitations techniques

Fonctionnalités impossibles à implémenter en pur Bash/LDAP.

---

## Sessions collection

**Problème** : Nécessite NetSessionEnum (API RPC/SMB Windows).

**Actuellement** : `"Sessions": {"Collected": true, "Results": []}`

**Alternative** : SharpHound ou RustHound-CE avec accès RPC.

**Impact** : Pas de détection de sessions actives. Graphe des connexions incomplet.

---

## AD CS (Certificate Services)

**Problème** : 
- Enterprise CAs stockent leurs données dans le registre Windows (pas LDAP)
- Certificate Templates ont des attributs binaires complexes (OIDs, bitfields)
- Parsing nécessiterait plusieurs centaines de lignes de code

**Actuellement** : Pas de collection AD CS.

**Alternative** : RustHound-CE ou Certify.exe

**Impact** : Pas de détection vulnérabilités PKI (ESC1-ESC8).

**Note** : Collection partielle techniquement possible (templates basiques depuis LDAP) mais sans les propriétés critiques pour la sécurité.

---

## DCRegistryData

**Problème** : Nécessite accès registre Windows distant via WinRM/RPC.

**Actuellement** : `"CertificateMappingMethods": null, "StrongCertificateBindingEnforcement": null`

**Impact** : Impossible de détecter les configurations PKI du DC.

---

## LocalAdmin collection

**Problème** : Nécessite interroger chaque machine via RPC (SAM-R) pour lister les admins locaux.

**Alternative** : SharpHound avec option LocalAdmin.

**Impact** : Pas de graphe des admins locaux. Chemins d'attaque incomplets vers les machines.

---

## LAPS password reading

**Problème** : L'attribut `ms-Mcs-AdmPwd` nécessite :
- Permissions spéciales (rarement accordées)
- Déchiffrement potentiel

**Actuellement** : Détection des ACLs `ReadLAPSPassword` possible, mais pas lecture effective du mot de passe.

**Impact** : On sait qui peut lire, mais on ne peut pas extraire les passwords.

---

## GPO parsing avancé

**Problème** : Les fichiers GPO sont stockés dans SYSVOL (`\\domain\SYSVOL\...`). Nécessite accès SMB et parsing XML.

**Actuellement** : Seulement métadonnées GPO depuis LDAP (DN, name, displayName, gPCFileSysPath).

**Alternative** : SharpGPOAbuse, PowerView

**Impact** : 
- Pas de parsing GPP passwords
- Pas de scheduled tasks
- Pas de scripts de démarrage
- Pas d'analyse des policies appliquées

---

## Résumé

Ces limitations sont inhérentes au choix technologique (pur Bash/LDAP). Pour un audit complet :

**Utiliser BashHound-CE pour** :
- Énumération AD de base
- ACLs et chemins d'attaque
- Détection highvalue groups
- Trusts et relations

**Utiliser en complément** :
- SharpHound / RustHound-CE : Sessions, LocalAdmin
- Certify / Certipy : AD CS
- PowerView / BloodHound-Python : Compléments divers

