# Let's Meet - Hackday 2026 CTF Writeup (Unsolved)

## Challenge Information
- **Name:** Let's meet
- **Category:** Web / SSRF
- **Points:** 500 (Hard)
- **URL:** https://xmywauknwa.hackday.fr
- **Status:** ⚠️ Not solved during the event

## Description

A web application challenge involving Server-Side Request Forgery (SSRF) to access an internal admin API and join an admin's meeting.

## Challenge Analysis

### Application Overview

The application is a meeting/appointment scheduler built with:
- **Backend:** Rocket (Rust web framework)
- **Database:** MongoDB
- **Features:** 
  - User registration and login
  - Calendar view
  - Appointment booking with members
  - Edit/delete appointments

### Key Information from note.txt

```
FROM: Samuel Sanders (admin_65537)
SUBJECT: Maintenance & New Dev Features

NEW FEATURE: ADMIN MEMBER MANAGEMENT
------------------------------------
Internal API (port 5000 ONLY):
curl "http://127.0.0.1:5000/api/admin/add-to-app?new_user=exampleuser&reference=exampleuser2-JAN1"

NOTE: POST requests to this route are automatically REDIRECTED to the GET handler.

NEW "SMART-NAV" FEATURE (BETA):
-------------------------------
Persistent replay buffer caches POST requests in MongoDB.
If a user deletes an appointment, the system can "replay" the stored request.

WARNING: Do not expose port 5000 to the public gateway.

Admin's meeting: August 21st (reference: admin_65537-AUG21)
```

### Goal

Trigger an SSRF to make the server call:
```
http://127.0.0.1:5000/api/admin/add-to-app?new_user=testuser123&reference=admin_65537-AUG21
```

This would add our user to the admin's meeting on August 21st.

## Reconnaissance

### Registration and Login

```powershell
$body = @{username="testuser123"; password="testpass123"; company="TestCorp"}
Invoke-WebRequest -Uri "https://xmywauknwa.hackday.fr/register" -Method POST -Body $body

$body = @{username="testuser123"; password="testpass123"}
Invoke-WebRequest -Uri "https://xmywauknwa.hackday.fr/login" -Method POST -Body $body -SessionVariable session
```

Session cookie format: JWT-like token with username and role.

### Application Endpoints

- `/` - Dashboard/calendar
- `/register` - User registration
- `/login` - User login
- `/account` - User profile and appointments
- `/book` - Create appointment (GET/POST)
- `/add_member` - Add member to appointment (POST)
- `/edit_appointment` - Edit appointment details (POST)
- `/leave_appointment` - Leave/delete appointment (POST)

### Booking Form Fields

```
name - Event name
month - Month (e.g., "JAN", "FEB", "AUG")
day - Day number
details - Additional details (textarea)
members - Comma-separated usernames
```

## Attempted Attack Vectors

### 1. URL Injection in Fields

Tried injecting SSRF URLs in various fields:

```powershell
# In details field
$body = @{
    name="Test"
    month="JAN"
    day="25"
    details="http://127.0.0.1:5000/api/admin/add-to-app?new_user=testuser123&reference=admin_65537-AUG21"
    members=""
}
```

**Result:** URL stored but HTML-encoded, not fetched by server.

### 2. URL in Month Field

```powershell
$body = @{
    name="SSRF"
    month="http://127.0.0.1:5000/api/admin/add-to-app?new_user=testuser123&reference=admin_65537-AUG21&x="
    day="1"
    details="test"
    members=""
}
```

**Result:** URL became part of reference ID (uppercased, dots removed from IP: `127001`), but no SSRF triggered.

### 3. Direct Reference Manipulation

Attempted to add ourselves to admin's meeting directly:

```powershell
$body = @{reference="admin_65537-AUG21"; new_member="testuser123"}
Invoke-WebRequest -Uri "https://xmywauknwa.hackday.fr/add_member" -Method POST -Body $body
```

**Result:** Silent failure - no error, but not added to admin's meeting.

### 4. NoSQL Injection

Attempted MongoDB operator injection:

```powershell
$body = "reference[`$regex]=admin.*-AUG21&new_member=testuser123"
Invoke-WebRequest -Uri "https://xmywauknwa.hackday.fr/add_member" -Method POST -Body $body
```

**Result:** No success.

### 5. Additional Hidden Parameters

Tried various parameter names that might trigger SSRF:

- `url=`
- `callback_url=`
- `replay_url=`
- `replay_to=`
- `webhook=`

**Result:** Parameters either ignored or caused 422 errors.

### 6. Looking for Replay Endpoints

Searched for Smart-Nav replay functionality:

```powershell
/replay, /rebook, /restore, /smart_nav, /smartnav, /quick_rebook
```

**Result:** All returned 404.

## Observations

### CSS Hint

The application includes a CSS class `.ssrf-alert` which strongly suggests SSRF is the intended vulnerability:

```css
.ssrf-alert {
    background-color: #fee2e2;
    border-left: 4px solid #ef4444;
    color: #991b1b;
    padding: 1rem;
    margin-bottom: 1.5rem;
    border-radius: 4px;
}
```

### POST to GET Redirect

The note mentions POST requests redirect to GET. This is a classic SSRF pattern where:
1. POST sent to internal API
2. Server redirects to GET with query parameters
3. GET request processes the parameters

### Smart-Nav Replay Mechanism

The replay buffer caches POST requests in MongoDB. The trigger mechanism for replay is unclear - possibilities:
- Automatic replay on deletion + re-booking
- Triggered by specific parameter
- Background process that replays requests
- Accessed via hidden endpoint

## Missing Pieces

What we didn't figure out:

1. **Replay Trigger:** How to trigger the Smart-Nav replay functionality
2. **Injection Point:** Which field or parameter causes server-side URL fetch
3. **Exact SSRF Vector:** The specific payload format that works

## Potential Solutions (Unverified)

### Theory 1: Replay on Delete + Rebook

1. Book an appointment with malicious data
2. Delete the appointment
3. Immediately rebook - server replays cached POST
4. If cached POST contains URL, server fetches it

### Theory 2: Hidden Parameter in MongoDB

The Smart-Nav might store additional fields in MongoDB that aren't in the HTML form. A parameter like `replay_callback` or similar could be in the POST data.

### Theory 3: Company Field SSRF

During registration, the `company` field might be used for lookups or webhooks that trigger SSRF.

## Tools Used

- **PowerShell** - HTTP requests and testing
- **Browser DevTools** - Form analysis
- **Burp Suite** (if available) - Request interception

## Lessons Learned

1. **Read hints carefully** - The POST→GET redirect and Smart-Nav replay are key hints
2. **MongoDB caching** - Cached requests might contain fields not visible in UI
3. **Hard challenges** - 500-point challenges may require multiple exploitation steps chained together
4. **Time management** - Sometimes it's better to move on and return later with fresh perspective

## Flag

```
HACKDAY{...}  # Not obtained
```

## Next Steps for Future Attempts

1. Set up local Rocket + MongoDB environment to test theories
2. Use proxy to intercept all requests and responses
3. Monitor MongoDB queries if possible
4. Try mass parameter fuzzing with tools like Arjun
5. Look for source code leaks or debug endpoints
6. Test if company name during registration triggers external lookup

---

**Note:** This writeup documents the analysis process even though the challenge wasn't solved. Understanding failed approaches is valuable for learning.
