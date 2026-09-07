# Revue d’architecture de sécurité des agents IA

## Sécuriser les agents IA avant leur connexion aux systèmes critiques de l’entreprise

Les agents IA connectés à Salesforce, à un CRM, à des serveurs MCP ou à des API d’entreprise introduisent de nouveaux risques. Une injection de prompt, un outil compromis ou des autorisations excessives peuvent exposer des secrets, contourner les contrôles d’approbation, modifier des données sensibles ou permettre l’accès à des systèmes non prévus.

La **Revue d’architecture de sécurité des agents IA** permet d’identifier ces risques avant la mise en production et de définir un plan de remédiation concret et priorisé.

## À qui s’adresse cette offre ?

Cette revue s’adresse aux entreprises de taille intermédiaire et aux organisations réglementées qui :

- développent ou expérimentent des agents IA connectés à Salesforce, à un CRM, à MCP ou à des API internes ;
- doivent protéger les données clients et les secrets applicatifs ;
- ont besoin de démontrer la traçabilité, le moindre privilège et la supervision humaine ;
- souhaitent une évaluation indépendante avant une mise en production.

## Risques évalués

- Usurpation d’identité d’un agent ou d’une charge de travail
- Autorisations excessives et élévation de privilèges
- Exposition ou réutilisation de secrets
- Utilisation abusive d’outils provoquée par une injection de prompt
- Absence d’approbation humaine pour les actions sensibles
- Server-Side Request Forgery (SSRF) et flux sortants non maîtrisés
- Injection dans les chemins et les paramètres
- Journalisation incomplète ou contenant des données sensibles
- Isolation réseau ou d’exécution insuffisante

## Périmètre de la revue

La prestation comprend généralement :

1. Un entretien de cadrage sur le cas d’usage, les données, les identités, les outils et les systèmes cibles.
2. L’analyse des frontières de confiance et des flux de bout en bout.
3. L’évaluation de l’identité des workloads, de l’audience des jetons, des scopes et de la gestion des secrets.
4. La revue des autorisations des outils, des politiques de sécurité et des contrôles Human-in-the-Loop.
5. L’analyse ciblée de scénarios d’attaque réalistes.
6. Un atelier de restitution et de priorisation avec les parties prenantes techniques et métier.

La prestation porte sur l’architecture et sur un ensemble d’éléments techniques représentatifs. Elle ne constitue ni un test d’intrusion complet, ni une certification de conformité, ni un audit exhaustif du code source.

## Livrables

- Schéma de l’architecture de sécurité existante
- Analyse des frontières de confiance et des flux d’identité
- Registre des risques priorisés
- Matrice des contrôles de sécurité
- Recommandations pour l’architecture cible
- Feuille de route de remédiation pragmatique
- Synthèse destinée aux décideurs

## Formules proposées

### Atelier de découverte

- Session de travail de 90 minutes
- Première évaluation de l’architecture et des risques
- Synthèse des questions prioritaires et des prochaines actions
- Tarif indicatif : **600 à 900 EUR**, selon la préparation et le périmètre

### Revue complète de l’architecture

- Durée habituelle : **5 à 10 jours ouvrés**
- Tarif indicatif : **3 000 à 6 000 EUR**, confirmé après le cadrage

Ces fourchettes constituent une première hypothèse commerciale. Elles pourront évoluer selon la complexité du système, le nombre d’intégrations et les éléments disponibles.

## Une approche démontrée par un POC

La méthodologie s’appuie sur un POC opérationnel de sécurité Zero Trust pour agents IA couvrant notamment :

- des conteneurs d’agents isolés et en lecture seule ;
- une segmentation des réseaux Docker ;
- des jetons d’identité de workload RS256 à durée de vie courte ;
- des autorisations et des scopes spécifiques à chaque agent ;
- l’isolation des secrets au moyen d’un broker de confiance ;
- l’application de politiques et l’approbation humaine ;
- la validation stricte des arguments et des ressources Salesforce ;
- des tests SSRF, d’injection de chemin, d’usurpation d’identité et d’élévation de privilèges ;
- des preuves d’audit ne contenant pas de secrets.

[Consulter le POC Zero-Trust Agent Security](GITHUB_REPOSITORY_URL)

## Prochaine étape

Planifiez un échange de 20 minutes afin de présenter votre cas d’usage, votre architecture actuelle et vos enjeux de mise en production.

**Friend Agent**  
[friend-agent.com](https://www.friend-agent.com/)  
[contact@friend-agent.com](mailto:contact@friend-agent.com)
