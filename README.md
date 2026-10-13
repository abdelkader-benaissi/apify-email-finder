# Email Finder

Find email addresses on any website over plain HTTP — **no headless browser, no waiting**. Built for **lead generation**, sales prospecting, and contact discovery: give it a list of sites and get back every email they publish.

Feed it one or more URLs and get back one dataset row per unique email: the address, the page where it was found, whether it came from the seed page or a discovered contact page, and the page title.

## What it does

- **HTTP-only fetching** — 30s timeout, browser-like User-Agent, follows redirects. A page scans in about a second.
- **Two extraction sources** — page text (robust regex) **and** `mailto:` links (query strings stripped, multiple recipients handled).
- **Automatic contact-page discovery** — finds same-domain links whose URL or anchor text mentions contact/about/team/impressum/legal and scans up to `contactPagesPerSite` of them. Contact pages are where the emails hide.
- **Deduped** — each email appears once per run, tagged with where it was first found.
- **False positives filtered** — skips asset filenames (`logo@2x.png`), `example.com`/`example.org` placeholders, and `noreply@`/`no-reply@` addresses.
- **Batch** — one URL per line; one bad URL never kills the batch.
- **Safe by default** — only public `http(s)` URLs are fetched; hosts resolving to private, loopback or link-local IPs are refused (SSRF guard).

## Input

| Field | Description |
|---|---|
| `urls` | Sites to scan, one URL per line (required) |
| `maxPages` | Max pages fetched per run, including contact pages (default 10, max 50) |
| `contactPagesPerSite` | Contact/about pages scanned per site (default 3, 0 disables) |

Example input:

```json
{
  "urls": "https://www.djangoproject.com\nhttps://www.python.org/about/",
  "maxPages": 10,
  "contactPagesPerSite": 3
}
```

## Output

One dataset row per unique email:

| Field | Description |
|---|---|
| `url` | Page where the email was found (after redirects) |
| `email` | The email address (lowercased) |
| `source` | `page` (seed page) or `contact-page` (discovered contact page) |
| `pageTitle` | Title of the page where it was found |

## Pricing

| Event | Price |
|---|---|
| Page scanned | **$0.002** per page successfully scanned |

You are charged per page scanned — not per email found — and only for pages that fetch successfully. Failed fetches cost nothing. (Apify platform usage costs are paid by you as usual.)
