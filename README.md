# Tower Defense 3D – s účty a cloudovým ukládáním

Hra běží v prohlížeči, server (Node.js) k ní přidává **registraci, přihlášení a ukládání postupu**
(🏅 mince, odemčené věže, výbava, rekordy). Hosting: **GitHub + Render**.

```
server.js          server: hra + API (/api/register, /api/login, /api/me, /api/save)
public/index.html  samotná hra (s přihlašovacím oknem)
render.yaml        předpis pro Render (web služba + PostgreSQL)
package.json       jediná závislost: pg
```

## Co hra umí (kromě účtů)
- **3 mapy** (výběr v menu): Klikatá louka, Pouštní spirála, Ledový zigzag – každá s jinou cestou a barvami. Po změně se stránka načte znovu, postup zůstává.
- **4 schopnosti hráče** s cooldowny: 💥 Nálet (Q, klikneš na mapu), ❄️ Mrazivá vlna (W), 💰 Dotace (E), 🛠️ Oprava základny (R).
- **Auto-vlny** (A) – další vlna se sama spustí 4 s po dokončení předchozí; **rychlost 1×/2×/3×** (F); otřesy kamery při zásahu základny a náletu.
- 10 typů věží (včetně 🤖 Továrny na roboty a ⚡ Elektrošokeru), módy Easy / Normal / Hard / Infinite, omračující nepřátelé a bossové.

## 1) Vyzkoušení lokálně (bez databáze)

```bash
npm install
npm start            # http://localhost:3000
```
Bez `DATABASE_URL` se účty ukládají do souboru `data/db.json` (jen pro vývoj).

## 2) Nahrání na GitHub

```bash
git init
git add .
git commit -m "Tower Defense 3D s účty"
git branch -M main
git remote add origin https://github.com/<tvoje-jmeno>/<repo>.git
git push -u origin main
```

## 3) Nasazení na Render

**Nejsnazší cesta – Blueprint:**
1. Na https://render.com → **New → Blueprint** → vyber svůj GitHub repozitář.
2. Render přečte `render.yaml`, vytvoří webovou službu i PostgreSQL databázi a sám nastaví
   `DATABASE_URL` a `JWT_SECRET`.
3. Po buildu otevři adresu `https://<nazev>.onrender.com` – hra běží a v menu je tlačítko **Přihlásit se**.

**Ručně:** New → Web Service (Build `npm install`, Start `npm start`), přidej proměnné
`NODE_ENV=production`, `JWT_SECRET=<dlouhý náhodný text>` a `DATABASE_URL=<adresa PostgreSQL>`.

### Důležité upozornění k free tarifu
- Free web služba po čase nečinnosti **usíná** – první načtení (a první přihlášení) pak trvá cca půl minuty až minutu.
- Free PostgreSQL na Renderu je **časově omezený** (po uplynutí lhůty se databáze smaže) – aktuální podmínky
  najdeš v dokumentaci Renderu. Pro trvalé účty buď přejdi na placený plán databáze, nebo použij externí
  free PostgreSQL (např. Neon nebo Supabase): v `render.yaml` smaž část `databases:` a u `DATABASE_URL`
  místo `fromDatabase` nastav hodnotu ručně v Render dashboardu.

## Jak ukládání funguje
- Postup se vždy ukládá i lokálně (localStorage), takže hra funguje i bez účtu a offline.
- Po přihlášení se každá změna (mince, nákup věže, rekord…) po chvilce odešle na server.
- Při přihlášení vyhrává novější postup; pokud je novější ten na zařízení, hra se zeptá, který použít.
- Odhlášení smaže postup z prohlížeče (aby na sdíleném počítači nezůstal cizí účet) – v cloudu zůstává.

## Bezpečnost a limity
- Hesla se ukládají jako hash (scrypt), přihlášení je podepsaný token s platností 30 dní.
- Přihlašování je omezené (po 10 špatných heslech se účet na chvíli zamkne, omezení i podle IP).
- Server kontroluje tvar a meze uloženého postupu, ale hra běží u hráče – postup si může upravit
  zkušený hráč (nejde o soutěžní žebříček). Není zde obnova hesla ani e-mail.
