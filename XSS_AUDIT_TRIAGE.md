# XSS Audit Triage — Full Code Path Analysis

**Date:** 2026-03-20
**Scope:** All 19 bugs from XSS_AUDIT_REPORT.md
**Goal:** Determine which are real security concerns vs code quality issues, which affect production users, and which matter for Amplify v2/v6 setups.

---

## TIER 1: REAL VULNERABILITIES — Exploitable in Production

### Bug #1 — DOM XSS in maplibre-gl-js-amplify popupRender.ts ✅ REAL

**Severity: High (downgraded from Critical)**
**Production code: YES** — `maplibre-gl-js-amplify` v4.0.0 is actively maintained and is a dependency of `@aws-amplify/ui-react-geo` (v2.3.2).
**Amplify v6: YES** — peer dependency is `aws-amplify: 6.x.x`.

**Code path traced:**
- `popupRender.ts:37-38` — GeoJSON `title`, `address`, `place_name` interpolated directly into HTML template literals with zero escaping
- `drawUnclusteredLayer.ts:90` — return value passed to MapLibre's `Popup.setHTML()` which parses raw HTML
- `utils.ts:70-77` — properties come directly from user-provided `Coordinate` objects via `drawPoints()`

**Why it's real:** If a developer calls `drawPoints()` with data from an untrusted source (e.g., a database, API, user input), any HTML in `title`/`address` properties executes in the browser. The `setHTML()` sink is a genuine DOM XSS vector.

**Realistic attack scenario:** Application stores place names from users → renders them on a map with `showMarkerPopup: true` → stored XSS.

**Mitigating factor:** If data comes exclusively from AWS Location Service, AWS likely sanitizes it server-side. But the code provides NO defense layer — a single misconfigured data source creates XSS.

---

### Bug #2 & #3 — innerHTML XSS in AmplifyGeofenceControl ✅ REAL (limited)

**Severity: Medium (downgraded from High)**
**Production code: YES** — same package as Bug #1.
**Amplify v6: YES**

**Code path traced:**
- `ui.ts:408` — `geofenceTitle.innerHTML = geofence.geofenceId` (list rendering)
- `ui.ts:607` — `title.innerHTML = \`...${geofenceId}...\`` (delete confirmation)
- Source: `Geo.listGeofences()` API response (AWS Amplify Geo)

**Why it's limited:** AWS Location Service enforces geofence ID format server-side. The local validation regex (`geofenceUtils.ts:10`) is `[-._\p{L}\p{N}]+` which does NOT permit `<`, `>`, `"`, or `'`. So HTML injection via geofence IDs requires either:
1. AWS API compromise/bypass
2. MITM attack on the API response
3. Future AWS API change relaxing validation

**Verdict:** Defense-in-depth issue. Using `textContent` instead of `innerHTML` would cost nothing and eliminate the risk entirely. Worth fixing but not immediately exploitable under normal conditions.

---

### Bug #11 — Template injection in createRedirectionIntermediary.ts ⚠️ LATENT/DESIGN FLAW

**Severity: Medium (downgraded from High)**
**Production code: YES** — `@aws-amplify/adapter-nextjs` (Next.js auth adapter)
**Amplify v6: YES**

**Code path traced:**
- `createRedirectionIntermediary.ts:14-25` — `redirectTarget` interpolated into `<meta>`, `<script>`, and `<a>` contexts with zero escaping
- `handleSignInCallbackRequest.ts:118` — `getRedirectOrDefault(handlerInput.redirectOnSignInComplete)`
- `getRedirectOrDefault.ts:4-5` — simply returns `redirect || '/'`
- `handlerInput.redirectOnSignInComplete` is from the **developer's Amplify config** (e.g., `amplify_outputs.json`)

**Why it's NOT currently exploitable:** The `redirectTarget` value is always developer-configured at build/deploy time. It never comes from URL parameters, cookies, or any user input. An attacker cannot influence this value.

**Why it still matters:** The function `createHTML()` is a textbook unsafe pattern. If ANY future code path passes dynamic data through it, instant XSS in three contexts simultaneously. This is a dangerous API design that should use proper escaping as defense-in-depth.

---

### Bug #12 — OAuth error_description passed unsanitized ⚠️ SHARED RESPONSIBILITY

**Severity: Medium (downgraded from High)**
**Production code: YES** — `@aws-amplify/auth` (core auth package)
**Amplify v6: YES**

**Code path traced:**
- `completeOAuthFlow.ts:40` — `urlParams.searchParams.get('error_description')` extracted from OAuth callback URL
- `completeOAuthFlow.ts:43` — `throw createOAuthError(errorMessage ?? error)`
- `createOAuthError.ts:8-17` — wraps it in an `AuthError` object with `message` property
- The error is thrown/dispatched — Amplify NEVER renders it to DOM itself

**Why it's limited:** Amplify correctly treats this as an error to be thrown. XSS only occurs if the **consuming application** renders the error message using `innerHTML` or `dangerouslySetInnerHTML`. If the app uses React's JSX rendering (`{error.message}`), React auto-escapes it.

**Verdict:** This is a shared responsibility issue. Amplify should document that error messages may contain untrusted content. But Amplify itself doesn't create the DOM XSS — the application does. Calling this an "Amplify XSS" is a stretch.

---

## TIER 2: NOT VULNERABILITIES — Code Quality / By-Design

### Bug #4 & #5 — javascript: href in Link/Breadcrumb components ❌ NOT A VULNERABILITY

**Severity: Informational**
**Production code: YES** — exported from `@aws-amplify/ui-react`
**Amplify v6: YES**

**Code path traced:**
- `BreadcrumbLink.tsx:50` → `Link.tsx:25` → `View` component → `React.createElement('a', {href})` → native `<a>` element
- The `href` is ALWAYS developer-provided via JSX props
- React (16.14 through 19) warns about but does NOT block `javascript:` URIs — this is React's intentional design

**Why it's not a vulnerability:**
1. The `href` prop is provided by the **developer writing the component**, not by end-user input
2. A developer writing `<Link href="javascript:alert(1)">` is doing so intentionally
3. React itself doesn't block this — should Amplify UI be stricter than React? No. That's not a component library's job.
4. No UI component library (Material UI, Chakra, Ant Design) validates href protocols

**Verdict:** This is equivalent to saying "React's `<a>` tag doesn't validate href protocols." True, but not a vulnerability in Amplify.

---

### Bug #6 — postMessage in ExpoSnack.tsx ❌ NOT A VULNERABILITY

**Severity: Informational**
**Production code: NO** — lives in `docs/src/components/` (documentation site only)
**Amplify v6: N/A**

**Why it's not a concern:** (Already analyzed in prior discussion)
1. Docs-site-only component, not shipped to users
2. The "leaked" data is publicly visible example code
3. Random iframe ID prevents blind exploitation
4. No DOM manipulation from incoming messages

---

### Bug #7 — postMessage in FlutterAuthenticatorExample.tsx ❌ NOT A VULNERABILITY

**Severity: Informational**
**Production code: NO** — documentation site component
**Amplify v6: N/A**

**Why it's not a concern:** The handler only calls `setHasLoaded(true)` — it toggles a loading spinner. An attacker could... hide a loading indicator on the docs site. The impact is nil.

---

### Bug #8, #9, #10 — discord-bot HTML injection ❌ NOT EXPLOITABLE

**Severity: Informational (downgraded from Critical/High)**
**Production code: Internal tooling** — AWS Amplify community Discord bot
**Amplify v6: N/A** — not part of Amplify SDK

**Code path traced:**
- `admin.ts:50` — unquoted `<img src=` with hardcoded DiceBear avatar URL
- `admin.ts:102` — `formatContent(message.content)` only handles code blocks, no HTML escaping
- `admin.ts:105` — Discord attachment URLs in `<img src="...">`
- All HTML → `postDiscussion()` → GitHub GraphQL API → GitHub Discussions

**Why it's not exploitable:** **GitHub Discussions sanitize HTML.** GitHub's markdown rendering pipeline strips:
- All event handler attributes (`onerror`, `onclick`, `onload`, etc.)
- `<script>` tags entirely
- `javascript:` URIs
- Most dangerous HTML constructs

So `<img src=x onerror=alert(1)>` becomes `<img src="x">` when rendered by GitHub. The XSS payload never executes.

**Additional context:**
- Bug #8's avatar URL is hardcoded to `https://avatars.dicebear.com/api/bottts/${userId}.svg` — not user-controlled
- The `/admin mirror` command requires Discord admin privileges to run
- This is an internal community tool, not part of the Amplify SDK

**Verdict:** Sloppy HTML generation, but GitHub's sanitization makes it non-exploitable. Code quality issue only.

---

### Bug #13 — customOAuthState Hub dispatch ❌ NOT EXPLOITABLE

**Severity: Informational (downgraded from Medium)**
**Production code: YES**
**Amplify v6: YES**

**Code path traced:**
- `completeOAuthFlow.ts:83` — `state` extracted from URL
- `completeOAuthFlow.ts:94` — `validateState(state)` called
- `validateState.ts:19` — `state === savedState` — **EXACT string comparison against stored random value**
- Only if state matches → custom state extracted and dispatched via Hub

**Why it's not exploitable:** The `validateState()` function requires the URL state to **exactly match** the state saved in `oAuthStore` (which was generated by Amplify during `signInWithRedirect`). An attacker cannot:
1. Predict the random state value
2. Modify the stored state (it's in the app's storage)
3. Forge a valid state parameter

The state validation is a complete blocker. Even if an attacker could forge state, the Hub dispatch sends data as a JavaScript object — React's JSX rendering would auto-escape it. XSS only occurs if the app uses `innerHTML` on the Hub event data.

---

### Bug #14 — includes() domain matching in getRedirectUrl.ts ⚠️ MINOR LOGIC BUG

**Severity: Low**
**Production code: YES**
**Amplify v6: YES**

**Code path traced:**
- `getRedirectUrl.ts:45-46` — `redirect.includes(String(window.location.hostname))` uses substring matching
- The `redirects` array is from the developer's Amplify config `oauth.redirectSignIn` / `oauth.redirectSignOut`

**Why it's limited:**
1. The redirect URLs are developer-configured — an attacker cannot add URLs to this list
2. An attacker would need their URL registered in the Cognito app client AND in the Amplify config
3. `isSameOriginAndPathName` (line 40-42) is tried FIRST and uses `startsWith` on origin+pathname — a much stronger check
4. `isTheSameDomain` is only the fallback

**Verdict:** Real logic bug in the domain matching algorithm, but practically unexploitable because the redirect URL list is developer-controlled. Worth fixing as defense-in-depth.

---

### Bug #15 — openAuthSession location.href assignment ❌ NOT A VULNERABILITY

**Severity: Informational (downgraded from Medium)**
**Production code: YES**
**Amplify v6: YES**

**Code path traced:**
- `openAuthSession.ts:11` — `window.location.href = url.replace('http://', 'https://')`
- Called only from Amplify's internal OAuth flow with URLs constructed by Amplify itself
- The URL is built from Cognito domain + client ID + redirect URIs — all from developer config

**Why it's not a vulnerability:**
1. The `url` parameter is never user-controlled
2. Modern browsers block `javascript:` in `location.href` assignment
3. The report itself acknowledges "the current callers pass internally-constructed OAuth URLs"

---

### Bug #16 — Inconsistent sanitization in codegen model-values.ts ⚠️ MINOR CODE QUALITY

**Severity: Low**
**Production code: Build-time tooling** — generates React components from Amplify Studio schemas
**Amplify v6: Amplify Studio (Gen 1 specific)**

**Code path traced:**
- `model-values.ts:616,623` — `factory.createIdentifier(bindingProperties.field)` without `escapePropertyValue()`
- `react-component-render-helper.ts:225-236` — same pattern WITH `escapePropertyValue()` applied

**Why it's limited:**
1. Schema data comes from **Amplify Studio** — an authenticated AWS Console feature
2. Only authenticated developers can create/modify schemas
3. Generated code is written to files that are committed and reviewed
4. The PoC (`__proto__`) creates `item?.__proto__` which is harmless in React component context
5. `createIdentifier()` only creates valid JS identifiers — can't inject arbitrary code

**Verdict:** Inconsistent sanitization is a code quality issue. But the attack requires compromising an AWS account to inject malicious schema data, at which point code generation is not the primary concern.

---

### Bug #17 — Component name as createIdentifier ❌ NOT A VULNERABILITY

**Severity: Informational**
**Production code: Build-time tooling**

**Why it's not a vulnerability:** `function constructor(props) { ... }` does NOT override JavaScript's constructor mechanism. It's just a function named "constructor" — valid JavaScript, harmless in practice. TypeScript's `createIdentifier` enforces valid identifier syntax.

---

### Bug #18 — Regex bypass in scriptingPatterns ❌ NOT A VULNERABILITY

**Severity: Informational**
**Production code: Build-time tooling**

**Why it's not a vulnerability:** These patterns are defense-in-depth checks during CODE GENERATION at build time. The generated code is:
1. Written to `.tsx` files
2. Committed to the repository
3. Reviewed by developers
4. Compiled by TypeScript (which would catch syntax errors)

Even if the regex is bypassed, the generated code goes through multiple review/compilation gates before reaching production.

---

### Bug #19 — dangerouslySetInnerHTML in Style.tsx ❌ NOT A VULNERABILITY

**Severity: Informational**
**Production code: YES** — `ThemeProvider` component
**Amplify v6: YES**

**Code path traced:**
- `Style.tsx:56` — `/<\/style/i.test(cssText)` blocks closing style tags
- `Style.tsx:64` — `dangerouslySetInnerHTML={{ __html: cssText }}`
- `cssText` comes from the theme configuration — developer-provided, not user input

**Why it's not a vulnerability:**
1. The `cssText` is generated from the developer's theme object, not from user input
2. The PoC is technically invalid — `url('...' + document.cookie)` does NOT work in CSS. CSS `url()` cannot execute JavaScript or concatenate strings.
3. The existing `</style` filter correctly prevents the one viable SSR attack vector (breaking out of the style tag)
4. `@import url()` could load external CSS, but only if the developer's theme config is attacker-controlled — at which point the attacker already has code-level access

---

## SUMMARY

### Bugs That Matter (fix recommended)

| # | Bug | Where | Real Severity | Why |
|---|-----|-------|---------------|-----|
| 1 | popupRender HTML injection | maplibre-gl-js-amplify | **High** | User data → setHTML() with no escaping. Real XSS if app passes untrusted data. |
| 2 | geofenceId innerHTML | maplibre-gl-js-amplify | **Medium** | Defense-in-depth: AWS validates IDs but code should use textContent. |
| 3 | geofenceId innerHTML (delete) | maplibre-gl-js-amplify | **Medium** | Same as #2, different sink location. |
| 11 | createHTML template injection | adapter-nextjs | **Medium** | Not currently exploitable but dangerous API pattern. Should escape. |
| 14 | includes() domain matching | amplify-js auth | **Low** | Logic bug in domain comparison. Should use proper URL parsing. |

### Bugs That Don't Matter (informational only)

| # | Bug | Why Not |
|---|-----|---------|
| 4,5 | javascript: href in Link/Breadcrumb | Developer-provided props, React's design, no user input path |
| 6,7 | postMessage in docs components | Docs site only, no sensitive data, no DOM manipulation |
| 8,9,10 | Discord bot HTML injection | GitHub sanitizes all HTML, internal tool, not part of SDK |
| 12 | OAuth error_description | Amplify throws error, never renders to DOM. App's responsibility to escape. |
| 13 | customOAuthState Hub dispatch | State validation blocks exploitation entirely |
| 15 | openAuthSession location.href | URL is never user-controlled, browsers block javascript: in location |
| 16 | Codegen missing escapePropertyValue | Build-time, requires AWS account compromise, generated code is reviewed |
| 17 | Component name as identifier | Naming a function "constructor" doesn't override anything |
| 18 | Regex bypass in scriptingPatterns | Build-time defense-in-depth, code goes through compilation + review |
| 19 | Style.tsx dangerouslySetInnerHTML | Theme is developer config, PoC is technically invalid, existing filter works |

### By Repository — What's Actually in Your Amplify v6 Setup

| Repository | In production? | In Amplify v6? | Real bugs? |
|------------|---------------|----------------|------------|
| **maplibre-gl-js-amplify** | YES (if using Geo) | YES (peer dep aws-amplify 6.x) | **#1 (High), #2-3 (Medium)** |
| **amplify-ui** | YES | YES | None real (docs-only + design issues) |
| **amplify-js** | YES | YES | **#11 (Medium), #14 (Low)** — latent, not currently exploitable |
| **discord-bot** | Internal tool | NO | None (GitHub sanitizes output) |
| **amplify-codegen-ui** | Build tool | Gen 1 Studio only | None real (build-time, auth-gated schemas) |

### Bottom Line

**Out of 19 reported bugs:**
- **1 is genuinely exploitable** in production (Bug #1 — maplibre popupRender)
- **2 are defense-in-depth fixes** worth making (Bugs #2-3 — innerHTML → textContent)
- **2 are latent risks** in amplify-js that should be hardened (Bugs #11, #14)
- **14 are informational** — code quality concerns, design choices, or non-exploitable patterns

The report dramatically overstated severity by not tracing data sources to determine if attacker-controlled input actually reaches the sinks. Most "High/Critical" findings assume attacker control of developer-configured values, AWS API responses, or build-time schema data.
