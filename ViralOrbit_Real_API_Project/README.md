# ViralOrbit Real API Project

## Run locally
```bash
npm install
cp .env.example .env
npm start
```

Open:
```text
http://localhost:3000
```

Default login:
```text
admin / 123456
```

## What is now real
- Express backend
- SQLite database
- Secure login with bcrypt
- JWT session
- Encrypted API credential storage with AES-256-GCM
- Real video file upload to backend `/api/videos/upload`
- Real publish endpoint `/api/publish`
- Real AI endpoint using OpenAI if `OPENAI_API_KEY` is set
- Frontend connected to backend upload/publish

## Credentials format to save in API fields

### YouTube
The backend requires OAuth credentials:
```json
{
  "client_id": "YOUR_GOOGLE_CLIENT_ID",
  "client_secret": "YOUR_GOOGLE_CLIENT_SECRET",
  "refresh_token": "YOUR_YOUTUBE_REFRESH_TOKEN",
  "redirect_uri": "http://localhost:3000/oauth2callback"
}
```
YouTube upload uses the Data API `videos.insert`.

### Facebook
```json
{
  "page_id": "YOUR_PAGE_ID",
  "page_access_token": "YOUR_PAGE_ACCESS_TOKEN"
}
```
Facebook video upload uses Graph API Page `/videos`.

### Instagram
Instagram reels publishing requires a public video URL accessible by Meta:
```json
{
  "ig_user_id": "YOUR_INSTAGRAM_BUSINESS_ACCOUNT_ID",
  "access_token": "YOUR_META_ACCESS_TOKEN"
}
```
Localhost video URLs will not work for Instagram. Deploy the backend or use a public HTTPS storage URL.

### TikTok
TikTok requires app approval and Content Posting API scopes:
```json
{
  "access_token": "YOUR_TIKTOK_ACCESS_TOKEN"
}
```
The code uses PULL_FROM_URL. The video URL must be public and usually from a verified domain/prefix.

### OpenAI AI generation
Put this in `.env`:
```env
OPENAI_API_KEY=sk-...
```

## Important
This code is now wired for real API calls, but it cannot publish until:
1. Your developer apps are approved.
2. OAuth access/refresh tokens are valid.
3. Required scopes are granted.
4. Instagram/TikTok can access your video through a public HTTPS URL.
5. Production secrets in `.env` are changed.
