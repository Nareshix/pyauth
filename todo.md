- sign up page (done)
- verify email page (done)
- login page 
- forget password (done)
- reset password (done)
- 2fa
- otp
- Resend Email Verification	
- Change Email / Password	
- Device Tracking / Session Management	
- Login with Phone Number (SMS)	
- Account Lockout	
- Rate Limiting / Throttling	
- Magic Link Login	
- OAuth / Social Login
- Webhooks for Auth Events
- Audit Logs	



Don't store plain or unsalted passwords in your database. Use modern techniques like storing metadata (algorithm, salt, version, etc) with the password hash in case you wanted to change it in the future, and only use reputable algorithms like Argon2, designed for password hashing. Password strength is key, so implement a checker. Don't keep users logged in indefinitely; refresh JWT tokens regularly, and generate new tokens after password changes. Try not to put unnecessary fields in JWTs and use standard protocols like OAuth or OpenID Connect for easy future changes and required integrations (e.g., Google). Sanitize inputs, rate-limit API requests to maybe 3 requests per minute to prevent certain bruteforce attacks, and consider using a captcha to prevent bot abuse. The rest is just optional luxury.



