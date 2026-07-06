# Password Reset & SSRF Chain - Verified Techniques

## Password Reset Broken Logic (Verified)

### Attack Flow
1. Request password reset for wiener (legitimate user)
2. Get reset token from email/exploit server
3. Intercept the POST /forgot-password request
4. Change hidden `username` field from wiener to carlos
5. Clear the `temp-forgot-password-token` field
6. Submit → carlos's password reset to attacker's value
7. Login as carlos

### Root Cause
```
# Vulnerable: server reads username from POST body, not from token
POST /forgot-password
temp-forgot-password-token=VALID_TOKEN
username=carlos          # <-- attacker changes this
new-password-1=hacked
new-password-2=hacked

# Server resets carlos's password using wiener's token
# Because: token is not bound to the user server-side
```

### Fix
```python
# Bind token to user server-side
token = get_reset_token(username=token_to_user[token])
if token and token.user == username:
    reset_password(username, new_password)
```

---

## SSRF via Open Redirect Chain (Verified)

### Attack Flow
1. Find stock check feature with URL parameter: `stockApi=http://internal/admin`
2. App blocks direct access to internal IPs
3. Find open redirect: `/product/nextProduct?currentProductId=1&path=ATTACKER_URL`
4. Chain: `stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos`
5. Server fetches the redirect endpoint → follows redirect → hits internal admin

### Root Cause
```
# Server validates initial URL (not internal IP)
# But follows redirects to internal URLs
# Fix: validate final resolved URL after following all redirects
```

### Key Lesson
**Always validate the FINAL resolved URL after following all redirects, not just the initial URL.**
