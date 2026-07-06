# Clickjacking - Lessons Learned

## Failed Lab: Basic clickjacking with CSRF token

### Issues Encountered
1. **Login failure**: wiener:peter returned "Invalid username or password" despite correct credentials
2. **Pixel alignment**: Tried 50+ positions (y=180-500, x=30-150), none matched
3. **Standard solution values**: top:300px, left:60px from walkthrough didn't work

### Root Cause
- Cannot determine exact button position without viewing the actual /my-account page
- Clickjacking requires precise pixel alignment between decoy and target button
- Automated testing without seeing the page layout is unreliable

### What Would Work
1. Login manually to view actual page layout
2. Inspect "Delete account" button position in browser DevTools
3. Use exact coordinates from rendered page
4. This is fundamentally hard to automate without browser inspection

### Key Lesson
**Clickjacking is one of the hardest vulnerabilities to automate.** It requires:
- Visual inspection of target page
- Precise pixel alignment
- Understanding of iframe rendering differences
- Manual tuning of overlay positions

This is why clickjacking labs typically score "APPRENTICE" level - they seem simple but require precise execution.
