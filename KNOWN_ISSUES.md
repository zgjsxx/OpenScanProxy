# Known Issues

## Portal Auth Compatibility Workaround

- Current portal auth includes a temporary compatibility workaround for browser pages.
- Requests that look like script-driven `fetch` / XHR traffic are currently allowed to bypass
  interactive portal auth when both conditions are true:
- `Sec-Fetch-Mode` is `cors` or `no-cors`
- `Sec-Fetch-Dest` is `empty`

### Why This Exists

- Redirecting those requests to `/login` breaks page rendering on modern sites.
- Typical failures include:
- API calls receiving HTML login pages instead of JSON
- media and image requests failing after redirect
- repeated login redirects triggered by subresource requests

### Security Note

- This is only a temporary compatibility mode.
- It is not the intended final security model for portal authentication.

### Intended Long-Term Fix

- Only top-level navigations should trigger portal login / bridge flow.
- Non-interactive subresource and API requests should not be redirected to portal.
- Bridge/bootstrap logic should prepare required site auth state before the real page loads.
