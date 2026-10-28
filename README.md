# Chapel of Praise Connect on Vercel

This package deploys the website and API on Vercel. It stores submissions, accounts, sessions, role passkeys, and the live testimony selection in Neon Postgres.

## 1. Create the database

1. Create a free Neon Postgres project at [Neon](https://neon.tech).
2. Copy its pooled connection string and keep it private.
3. In the Neon SQL Editor, run the full contents of `schema.sql`.

## 2. Deploy to Vercel

Open PowerShell in this folder and run:

```powershell
npm install
npx vercel login
npx vercel
```

During the first deploy, link or create a Vercel project. In the Vercel project settings, create these Production environment variables:

| Variable | Value |
| --- | --- |
| `DATABASE_URL` | The private Neon pooled connection string |
| `BOOTSTRAP_SECRET` | A long, private value used once to create the first superadmin |

Redeploy after adding the variables:

```powershell
npx vercel --prod
```

## 3. Create the first superadmin

Replace every sample value, then run this command with your deployed Vercel URL:

```powershell
$body = @{ username = 'TaiwoOluwalanke'; password = 'ChooseA12CharacterPassword'; passkey = 'ChooseASuperadminRolePasskey'; bootstrapSecret = 'YOUR-BOOTSTRAP-SECRET' } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'https://YOUR-PROJECT.vercel.app/api/bootstrap' -ContentType 'application/json' -Body $body
```

Open the Vercel URL and sign in. The superadmin can then create staff accounts using the appropriate role passkeys. `POST /api/admin/role-passkeys` sets the passkey for each role; it requires a signed-in superadmin session.

## Local preview

Create `.env` with the two environment variables, then run:

```powershell
npx vercel dev
```

Do not add `.env` or database credentials to Git.
