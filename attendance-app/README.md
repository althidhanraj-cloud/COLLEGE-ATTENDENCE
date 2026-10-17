# GPS Attendance (Admin + Student)

Run locally: `npm install` then `npm start` (opens on http://localhost:3000).
First start creates the admin: ID `admin`, password `admin123` (or set ADMIN_USER, ADMIN_PASS and ADMIN_NAME before the very first start; that account becomes the owner admin). Change it after login.

To let everyone use it: deploy to any Node host (Render, Railway, a VPS) with a persistent disk for attendance.db.
It MUST be served over HTTPS, otherwise phones will not give GPS to the website.
Set the DB path with DB_FILE if the host mounts a disk elsewhere.
Phones: open the site, then "Add to Home screen" to install it like an app.
