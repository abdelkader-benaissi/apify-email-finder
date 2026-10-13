"""Email Finder actor: extract email addresses from web pages over plain HTTP.

Each public URL is fetched over plain HTTP (no headless browser), email
addresses are extracted from the page text and from mailto: links, and then
same-domain contact/about pages are discovered and scanned too. Emails are
deduped per run and common false positives are filtered out.

Pay-per-event charges ("page-scanned") are emitted once per successfully
scanned page — never per email, never on failure — and only after the page's
items have been pushed to the dataset.
"""

import asyncio
import ipaddress
import re
import socket
from urllib.parse import unquote, urldefrag, urljoin, urlparse

import httpx
from apify import Actor
from bs4 import BeautifulSoup

EVENT_PAGE = 'page-scanned'

REQUEST_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')

# TLDs that indicate an image/asset filename rather than an email domain.
BAD_TLDS = ('.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.svg',
            '.webp', '.ico', '.woff', '.woff2', '.map')
EXAMPLE_DOMAINS = ('example.com', 'example.org', 'example.net')
NOREPLY_LOCALS = ('noreply', 'no-reply')

# Hints (in link URL or anchor text) that a same-domain link is a contact page.
CONTACT_HINTS = ('contact', 'about', 'team', 'impressum', 'legal')


async def check_public_url(url: str) -> tuple[bool, str]:
    """SSRF guard: only allow http(s) URLs that resolve to public IPs."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, 'malformed URL'
    if parsed.scheme not in ('http', 'https'):
        return False, f"unsupported scheme '{parsed.scheme}' (only http/https allowed)"
    host = parsed.hostname
    if not host:
        return False, 'missing hostname'
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return False, 'DNS resolution failed'
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False, f'resolves to non-public IP {ip}'
    return True, ''


def is_valid_email(candidate: str) -> bool:
    """Filter false positives: asset filenames, example domains, noreply."""
    email = candidate.strip().lower().rstrip('.,;:!?)\'"')
    if not EMAIL_RE.fullmatch(email):
        return False
    local, _, domain = email.partition('@')
    if not local or not domain:
        return False
    if domain in EXAMPLE_DOMAINS or any(
            domain.endswith('.' + d) for d in EXAMPLE_DOMAINS):
        return False
    if any(domain.endswith(tld) for tld in BAD_TLDS):
        return False
    if local in NOREPLY_LOCALS:
        return False
    return True


def extract_emails(html: str) -> list[str]:
    """Extract email addresses from page text and mailto: links, in order."""
    soup = BeautifulSoup(html, 'lxml')
    found: list[str] = []

    # 1) mailto: links (strip query strings, handle multiple recipients).
    for tag in soup.select('a[href^="mailto:"]'):
        href = tag.get('href', '')[len('mailto:'):].split('?', 1)[0]
        for part in unquote(href).split(','):
            part = part.strip()
            if part and is_valid_email(part):
                found.append(part.strip().lower())

    # 2) visible text.
    text = soup.get_text(separator=' ')
    for match in EMAIL_RE.findall(text):
        if is_valid_email(match):
            found.append(match.strip().lower())

    # Dedupe, preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for email in found:
        if email not in seen:
            seen.add(email)
            unique.append(email)
    return unique


def page_title(html: str) -> str | None:
    soup = BeautifulSoup(html, 'lxml')
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
        return title or None
    return None


def find_contact_links(html: str, page_url: str) -> list[str]:
    """Same-domain links whose URL or anchor text looks like a contact page."""
    base_netloc = (urlparse(page_url).hostname or '').lower()
    page_clean, _ = urldefrag(page_url)
    links: list[str] = []
    seen: set[str] = set()
    soup = BeautifulSoup(html, 'lxml')
    for tag in soup.find_all('a', href=True):
        href = (tag.get('href') or '').strip()
        if not href or href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            continue
        abs_url = urljoin(page_url, href)
        parsed = urlparse(abs_url)
        if parsed.scheme not in ('http', 'https'):
            continue
        if (parsed.hostname or '').lower() != base_netloc:
            continue
        clean, _ = urldefrag(abs_url)
        if clean == page_clean or clean in seen:
            continue
        haystack = (parsed.path + ' ' + tag.get_text(' ', strip=True)).lower()
        if any(hint in haystack for hint in CONTACT_HINTS):
            seen.add(clean)
            links.append(clean)
    return links


async def fetch_page(client: httpx.AsyncClient,
                     url: str) -> tuple[str | None, str, str]:
    """Fetch one URL. Returns (html_or_None, final_url, reason).

    Never raises; every failure is reported via the reason string.
    """
    ok, reason = await check_public_url(url)
    if not ok:
        return None, url, f'blocked: {reason}'
    try:
        resp = await client.get(url, timeout=30.0, follow_redirects=True)
    except httpx.TimeoutException:
        return None, url, 'fetch timed out after 30s'
    except httpx.HTTPError as exc:
        return None, url, f'fetch failed: {type(exc).__name__}'
    except Exception as exc:  # defensive: never kill the batch
        return None, url, f'fetch failed: {type(exc).__name__}'

    if resp.status_code >= 400:
        return None, url, f'HTTP {resp.status_code}'
    content_type = resp.headers.get('content-type', '').lower()
    if not any(t in content_type for t in ('html', 'text', 'xml')):
        return None, url, f'unsupported content type: {content_type}'
    return resp.text, str(resp.url), ''


async def charge_event(event_name: str) -> None:
    """Bill one pay-per-event charge. Never let billing break the run."""
    try:
        await Actor.charge(event_name=event_name)
    except Exception as exc:
        Actor.log.warning(f'Pay-per-event charge {event_name!r} failed: {exc}')


def parse_urls(raw) -> list[str]:
    if isinstance(raw, str):
        return [u.strip() for u in raw.splitlines() if u.strip()]
    if isinstance(raw, (list, tuple)):
        return [str(u).strip() for u in raw if str(u).strip()]
    return []


def build_client() -> httpx.AsyncClient:
    """Build the HTTP client.

    Falls back to ignoring environment proxies if the environment's proxy
    config is malformed — a broken proxy config must not kill runs.
    """
    try:
        return httpx.AsyncClient(headers=REQUEST_HEADERS,
                                 follow_redirects=True, timeout=30.0)
    except Exception as exc:
        Actor.log.warning(f'Unusable proxy environment ({exc}); '
                          'continuing without env proxies.')
        return httpx.AsyncClient(headers=REQUEST_HEADERS,
                                 follow_redirects=True, timeout=30.0,
                                 trust_env=False)


async def scan_page(client: httpx.AsyncClient, url: str, source: str,
                    seen: set[str], pages: dict
                    ) -> tuple[int, str | None, str]:
    """Fetch one page, push new email items, then charge for the scan.

    Returns (emails_pushed, html_or_None, final_url). Push happens BEFORE the
    charge, so a failed push never bills the customer. The charge fires once
    per successfully scanned page, even when it contains no emails.
    """
    html, final_url, reason = await fetch_page(client, url)
    if html is None:
        Actor.log.warning(f'Skipping {url}: {reason}')
        return 0, None, url
    title = page_title(html)
    pushed = 0
    for email in extract_emails(html):
        if email in seen:
            continue
        item = {'url': final_url, 'email': email,
                'source': source, 'pageTitle': title}
        await Actor.push_data(item)
        seen.add(email)
        pushed += 1
    pages['scanned'] += 1
    await charge_event(EVENT_PAGE)
    return pushed, html, final_url


async def main() -> None:
    async with Actor:
        inp = await Actor.get_input() or {}
        urls = parse_urls(inp.get('urls'))
        try:
            max_pages = int(inp.get('maxPages') or 10)
        except (TypeError, ValueError):
            max_pages = 10
        max_pages = max(1, min(max_pages, 50))
        try:
            contact_per_site = int(inp.get('contactPagesPerSite', 3) or 0)
        except (TypeError, ValueError):
            contact_per_site = 3
        contact_per_site = max(0, min(contact_per_site, 10))

        if not urls:
            await Actor.set_value('OUTPUT', {
                'sites': 0, 'pagesScanned': 0, 'emailsFound': 0,
                'error': 'no URLs provided',
            })
            return

        seen: set[str] = set()
        pages = {'scanned': 0}
        emails_found = 0
        async with build_client() as client:
            for seed_url in urls:
                if pages['scanned'] >= max_pages:
                    break
                # Main page.
                pushed, html, final_url = await scan_page(
                    client, seed_url, 'page', seen, pages)
                if html is None:
                    continue
                emails_found += pushed

                # Contact/about pages on the same domain.
                if contact_per_site > 0:
                    for contact_url in find_contact_links(
                            html, final_url)[:contact_per_site]:
                        if pages['scanned'] >= max_pages:
                            break
                        pushed, _, _ = await scan_page(
                            client, contact_url, 'contact-page', seen, pages)
                        emails_found += pushed

        await Actor.set_value('OUTPUT', {
            'sites': len(urls),
            'pagesScanned': pages['scanned'],
            'emailsFound': emails_found,
        })
