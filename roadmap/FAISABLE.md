# Améliorations possibles

Liste des fonctionnalités qui peuvent être implémentées en pur Bash/LDAP.

---

## Priorité haute

### Extraction whenCreated pour les Containers
Les containers ont actuellement `whencreated: -1`. L'attribut LDAP existe déjà dans les collectes, il faut juste le parser dans l'export.

**Fichiers** : `lib/collectors.sh`, `lib/export_ce.sh`

### Support propriétés de politique de mot de passe
Valeurs actuellement hardcodées dans l'export. Attributs LDAP à parser :
- minPwdLength
- pwdProperties  
- pwdHistoryLength
- lockoutThreshold
- lockoutDuration
- minPwdAge / maxPwdAge

**Fichiers** : `lib/collectors.sh`, `lib/ldap_parser.sh`, `lib/export_ce.sh`

### Functional Level detection
Actuellement "Unknown". Parser `msDS-Behavior-Version` :
- 0 = Windows 2000
- 2 = Windows Server 2003
- 3 = Windows Server 2008
- 4 = Windows Server 2008 R2
- 5 = Windows Server 2012
- 6 = Windows Server 2012 R2
- 7 = Windows Server 2016

**Fichiers** : `lib/collectors.sh`, `lib/export_ce.sh`

---

## Priorité moyenne

### SPNTargets parsing
Actuellement vide. Parser les SPNs des users et résoudre vers les computers cibles pour Kerberoasting.

Logique : extraire hostname du SPN, matcher avec dNSHostName des computers collectés.

**Fichiers** : `lib/export_ce.sh`

### HasSIDHistory
Actuellement vide. Parser l'attribut `sIDHistory` pour détecter migrations de domaines.

**Fichiers** : `lib/collectors.sh`, `lib/ldap_parser.sh`, `lib/export_ce.sh`

### AllowedToDelegate
Actuellement vide. Parser `msDS-AllowedToDelegateTo` pour délégation Kerberos contrainte.

**Fichiers** : `lib/collectors.sh`, `lib/ldap_parser.sh`, `lib/export_ce.sh`

### Highvalue detection pour Users
Actuellement les users ne sont jamais highvalue. Détecter :
- adminCount=1
- Appartenance aux groupes highvalue
- Comptes système (krbtgt, etc.)

**Fichiers** : `lib/export_ce.sh`

### SupportedEncryptionTypes
Actuellement vide. Parser `msDS-SupportedEncryptionTypes` (bitmask) :
- 0x01 = DES-CBC-CRC
- 0x02 = DES-CBC-MD5  
- 0x04 = RC4-HMAC
- 0x08 = AES128
- 0x10 = AES256

**Fichiers** : `lib/collectors.sh`, `lib/ldap_parser.sh`, `lib/export_ce.sh`

---

## Améliorations qualité

### Robustesse parsing timestamps
Différents serveurs AD encodent différemment (GeneralizedTime vs FileTime vs ASCII). Améliorer la détection et conversion.

**Fichiers** : `lib/ldap_parser.sh`

### Tests multi-environnements
Tester sur :
- Windows Server 2008 R2 / 2012 / 2016 / 2019 / 2022
- Différents niveaux fonctionnels
- Domaines avec/sans trusts
- Gros domaines (>10k objets)

### Optimisation performances
- Parallélisation des requêtes LDAP
- Optimisation regex et parsing
- Réduction appels externes (grep/sed)
- Cache pour résolutions DN → SID

### Gestion d'erreurs
- Messages d'erreur plus explicites
- Retry logic pour timeouts LDAP
- Détection permissions insuffisantes
- Logs détaillés en mode verbose

---

## Notes

Toujours comparer les sorties avec RustHound-CE pour validation.
Tester sur plusieurs domaines avant de merger.
