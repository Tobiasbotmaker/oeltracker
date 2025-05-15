# Øl Tracker

Øl Tracker er en webapplikation, der hjælper dig med at holde styr på dine venner, ølstatistik og meget mere. Applikationen er designet til at være sjov og engagerende, samtidig med at den giver brugerne mulighed for at sammenligne deres ølforbrug med venner og andre brugere.

## Funktioner
- **Brugerprofiler:** Opret og administrer din egen profil, inklusive profilbillede.
- **Vennefunktioner:** Tilføj venner, send venneanmodninger, og se venners ølstatistik.
- **Leaderboard:** Sammenlign ølforbrug med andre brugere over forskellige tidsperioder.
- **Kortvisning:** Se, hvor du og dine venner har drukket øl, ved hjælp af geolokation.
- **Ølanbefalinger:** Få forslag til, hvilken øl du skal drikke næste gang.
- **Adminpanel:** Administrer brugere og data som administrator.
- **Cookie- og privatlivspolitik:** Overholdelse af GDPR med klare politikker for cookies og privatliv.

---

## Teknologier brugt
Dette projekt bruger følgende open source-teknologier og ressourcer:

### **Backend**
- [Flask](https://flask.palletsprojects.com/) - Web framework (MIT-licens)
- [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/) - Database ORM (MIT-licens)
- [Flask-Migrate](https://flask-migrate.readthedocs.io/) - Database migrations (MIT-licens)
- [Flask-WTF](https://flask-wtf.readthedocs.io/) - CSRF-beskyttelse og formularhåndtering (BSD-licens)
- [Flask-Session](https://pythonhosted.org/Flask-Session/) - Server-side session management (MIT-licens)
- [Flask-Caching](https://flask-caching.readthedocs.io/) - Caching til forbedret ydeevne (BSD-licens)
- [Flask-Compress](https://flask-compress.readthedocs.io/) - Komprimering af HTTP-responser (MIT-licens)

### **Frontend**
- [Bootstrap](https://getbootstrap.com/) - Frontend framework til styling og layout (MIT-licens)
- [Bootstrap Icons](https://icons.getbootstrap.com/) - Ikoner til UI-elementer (MIT-licens)
- [Jinja2](https://jinja.palletsprojects.com/) - Templating-motor til dynamisk HTML (BSD-licens)

### **Andre ressourcer**
- [Leaflet](https://leafletjs.com/) - Kortvisning og geolokation (BSD-licens)
- [Pillow](https://python-pillow.org/) - Billedbehandling til profilbilleder (HPND-licens)
- [jQuery](https://jquery.com/) - JavaScript-bibliotek til DOM-manipulation (MIT-licens)

### **Billeder**
- Standardprofilbillede: Hentet fra [Pixabay](https://pixabay.com/) (CC0-licens).

---

## Installation

### **Krav**
- Python 3.8 eller nyere
- En PostgreSQL-database
- Virtuelt miljø (valgfrit, men anbefales)

### **Trin til installation**
1. **Klon projektet:**
   ```bash
   git clone <repository-url>
   cd beerspil