# Deployment Guide — Secure Lens AI on Render

This guide walks you through deploying Secure Lens AI to Render, a modern cloud platform with free tier support.

---

## Prerequisites

- GitHub account with your SecureLensAI repository
- Render account (free tier available at https://render.com)
- OpenAI API key (optional, for AI-powered analysis)

---

## Step 1: Prepare Your Repository

### 1a. Commit and Push to GitHub

On your local machine:

```bash
cd SecureLensAI
git add README.md render.yaml Procfile DEPLOYMENT_GUIDE.md
git commit -m "chore: add deployment configuration for Render"
git push origin main
```

**Important:** Ensure your `.env` file is NOT committed. It should be listed in `.gitignore`.

### 1b. Verify .gitignore

Your `.gitignore` should include:

```
.env
*.db
*.db-shm
*.db-wal
venv/
__pycache__/
uploads/*
node_modules/
```

---

## Step 2: Create a Render Account & Connect GitHub

1. Go to https://render.com
2. Sign up with your GitHub account
3. Authorize Render to access your GitHub repositories
4. Click **"New +"** → **"Web Service"**
5. Select your **SecureLensAI** repository
6. Accept the defaults (Render will detect the `render.yaml`)

---

## Step 3: Configure the Web Service

### Service Settings

**Name:** `secure-lens-ai` (or your preferred name)

**Region:** Select the region closest to your users (e.g., `oregon`, `frankfurt`, `singapore`)

**Branch:** `main`

**Runtime:** Python 3.10

**Build Command:**
```bash
cd backend && pip install -r requirements.txt || true
```

**Start Command:**
```bash
cd backend && python run.py
```

### Environment Variables

Click **"Add Environment Variable"** and add the following:

| Key | Value | Notes |
|-----|-------|-------|
| `FLASK_ENV` | `production` | Required |
| `SECRET_KEY` | *(generate new)* | Use `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `JWT_SECRET_KEY` | *(generate new)* | Use `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `OPENAI_API_KEY` | *(your key)* | Optional; leave blank for rule-based analysis only |
| `CORS_ORIGINS` | `https://yourdomain.com` | Update after you get your Render URL |
| `DATABASE_URL` | (leave blank) | Uses SQLite by default |
| `PORT` | `5000` | Render will pass PORT as env var |
| `HOST` | `0.0.0.0` | Required for Render |

**To generate SECRET_KEY and JWT_SECRET_KEY**, run on your local machine:

```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))"
```

Copy the output into Render's environment variable settings.

---

## Step 4: Configure Disk Storage (Persistent Database)

Render uses ephemeral storage by default, which means your database will be lost on restart. To keep data persistent:

1. In the Render dashboard, go to **"Disks"**
2. Click **"Add Disk"**
3. Set:
   - **Name:** `sqlite-data`
   - **Mount Path:** `/var/data`
   - **Size:** 1 GB (free tier allows 10 GB)

4. Update the `backend/config.py` to use the mounted disk:

```python
DATABASE_URL = "sqlite:////var/data/securelensai.db"  # For Render with mounted disk
```

*(The render.yaml already specifies this disk mount.)*

---

## Step 5: Deploy

1. In the Render dashboard, click **"Deploy"**
2. Watch the build logs for errors
3. Once the build completes, you'll get a URL like:
   ```
   https://secure-lens-ai.onrender.com
   ```

---

## Step 6: Update CORS Origins

Now that you have your Render URL, update the `CORS_ORIGINS` environment variable:

1. Go back to the Web Service settings
2. Edit the `CORS_ORIGINS` variable to:
   ```
   https://secure-lens-ai.onrender.com
   ```
3. Redeploy

---

## Step 7: Test the Deployment

1. Open your Render URL in a browser
2. You should see the Secure Lens AI login page
3. Create a new account
4. Try uploading a sample log file
5. Verify the analysis works

---

## Step 8: Set Up Auto-Deploy (Optional)

By default, Render auto-deploys on every push to `main`. To disable:

1. Go to **"Settings"** → **"Deploy Hook"**
2. If you want manual deploys, disable auto-deploy and use the webhook manually

---

## Troubleshooting

### Build Failures

Check the **"Logs"** tab in Render for error messages. Common issues:

- **ModuleNotFoundError:** The `backend/vendor/` shim packages may not be found. Ensure they're committed to GitHub.
- **Port binding error:** Verify `PORT` and `HOST` are set in environment variables.
- **Database errors:** Check that `DATABASE_URL` matches the disk mount path.

### Runtime Errors

Look at **"Logs"** → **"Runtime"** for errors:

- **404 on /api/health:** The backend is not starting. Check the start command.
- **CORS errors:** Ensure `CORS_ORIGINS` includes your Render URL.
- **File upload fails:** Check disk permissions; ensure uploads directory is writable.

### Database Issues

If data is lost on redeploy:

1. Verify the disk is mounted (Render dashboard → Disks)
2. Check that `backend/config.py` uses the correct disk path
3. Manually redeploy to ensure changes take effect

---

## Frontend Deployment (Optional)

Currently, the frontend and backend are served together. If you want to serve them separately:

1. Deploy the `frontend/` directory to Vercel or Netlify
2. Update the API URL in `frontend/js/api-client.js`:
   ```javascript
   const API_URL = 'https://secure-lens-ai.onrender.com/api';
   ```
3. Update `CORS_ORIGINS` to include the frontend URL

---

## Monitoring & Maintenance

- **View Logs:** Render dashboard → Logs tab
- **Monitor Metrics:** Render dashboard → Metrics (CPU, memory, requests)
- **Update Variables:** Environment variables can be updated without redeploy
- **Restart Service:** Click the "Restart" button in the Render dashboard
- **Scale Resources:** Upgrade to a paid Render plan for more CPU/memory

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| **"Module not found" errors** | Ensure `backend/vendor/` is committed and all `__init__.py` files exist |
| **Database file not persisting** | Verify disk is mounted and `DATABASE_URL` points to `/var/data` |
| **CORS errors in browser** | Update `CORS_ORIGINS` to match your Render URL (https://...) |
| **API timeout (503 errors)** | Backend may be slow to start; increase timeout or upgrade Render plan |
| **Free tier sleeping** | Render free tier services sleep after 15 min of inactivity; upgrade to always-on |

---

## Next Steps

1. **Domain name:** Connect a custom domain through Render (paid feature)
2. **SSL certificate:** Render provides free SSL for all services
3. **Backups:** Set up database backups manually or use a third-party service
4. **Monitoring:** Integrate with external monitoring (e.g., Sentry for error tracking)

---

**Questions?** Check the Render documentation: https://render.com/docs
