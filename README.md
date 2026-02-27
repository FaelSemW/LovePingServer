# LovePing (Railway) — onde colocar

## O que vem no zip
- main.py (backend + site + websocket)
- requirements.txt
- Procfile
- app/templates (HTML)
- app/static (CSS)

## Onde colocar
Você coloca esses arquivos na RAIZ de um repositório do GitHub.
Exemplo (estrutura do repo):
LovePingServer/
  main.py
  requirements.txt
  Procfile
  app/
    templates/
    static/

## Como colocar no ar (Railway)
1) GitHub: crie o repo e suba os arquivos
2) Railway: New Project -> Deploy from GitHub Repo -> escolha o repo
3) Railway > Variables:
   - JWT_SECRET = uma string grande
   - COOKIE_SECURE = true

## Spotify (para linkar 1 vez no site)
Railway > Variables:
- SPOTIFY_CLIENT_ID
- SPOTIFY_CLIENT_SECRET
- SPOTIFY_REDIRECT_URI = https://SEU_DOMINIO.up.railway.app/spotify/callback

Spotify Dashboard:
- Redirect URI deve ser exatamente o mesmo.

## Testes
- https://SEU_DOMINIO.up.railway.app/health
- Site: /register -> /dashboard -> Conectar Spotify
