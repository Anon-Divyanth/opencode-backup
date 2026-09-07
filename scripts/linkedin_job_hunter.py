#!/usr/bin/env python3
"""
LinkedIn Job Hunter - Playwright-based automation
Searches for cybersecurity fresher positions and outputs structured results.

Usage:
  python3 linkedin_job_hunter.py              # Run job search (headless, requires session)
  python3 linkedin_job_hunter.py --setup      # First-time setup (opens browser for login)
"""

import json
import sys
import os
import re
import argparse
from datetime import datetime
from pathlib import Path
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

# Configuration
SEARCH_QUERY = '"VAPT" OR "penetration tester" OR "web application security" OR "cyber security"'
USER_DATA_DIR = os.path.expanduser("~/.config/opencode/linkedin_profile")
RESULTS_DIR = "/tmp"

def check_session_exists():
    """Check if LinkedIn session directory exists and has data."""
    profile_path = Path(USER_DATA_DIR)
    if not profile_path.exists():
        return False
    # Check for cookies or login data
    cookies_file = profile_path / "Default" / "Cookies"
    return cookies_file.exists() or any(profile_path.rglob("*.cookies"))

def wait_for_login(page, timeout=300000):
    """Wait for user to complete LinkedIn login (5 min timeout)."""
    print("[*] Waiting for LinkedIn login (5 min timeout)...", file=sys.stderr)
    try:
        # Wait for URL to change from login page or for nav element
        page.wait_for_url("**/feed/**", timeout=timeout)
        print("[+] Login detected (redirected to feed)", file=sys.stderr)
        return True
    except PlaywrightTimeout:
        # Check if we're still on login page
        if "login" in page.url:
            print("[-] Login timeout - still on login page", file=sys.stderr)
            return False
        # We might be logged in but on a different page
        print("[+] Login appears successful", file=sys.stderr)
        return True

def verify_login(page):
    """Verify logged in as expected user."""
    try:
        # Check for profile nav element or feed content
        page.wait_for_selector('.global-nav__me, [data-test-app-aware-link], .feed-identity-module', timeout=10000)
        print("[+] Verified: Logged into LinkedIn", file=sys.stderr)
        return True
    except PlaywrightTimeout:
        print("[-] Not logged in", file=sys.stderr)
        return False

def search_linkedin(page, query):
    """Enter search query in LinkedIn search."""
    print(f"[*] Searching: {query}", file=sys.stderr)
    try:
        # Go to LinkedIn feed first
        page.goto("https://www.linkedin.com/feed/", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(3000)

        # Find and use search box
        search_input = page.locator('input[aria-label="Search"], input[placeholder*="Search"], input[type="text"]').first
        search_input.click()
        search_input.fill(query)
        search_input.press("Enter")
        page.wait_for_timeout(3000)
        return True
    except Exception as e:
        print(f"[-] Search failed: {e}", file=sys.stderr)
        return False

def filter_by_posts(page):
    """Switch to Posts filter."""
    print("[*] Filtering by Posts", file=sys.stderr)
    try:
        # Click on Posts filter
        posts_btn = page.locator('button:has-text("Posts"), a:has-text("Posts"), [data-test="search-reusables__filter-pill-posts"]').first
        posts_btn.click()
        page.wait_for_timeout(2000)
        return True
    except Exception as e:
        print(f"[-] Posts filter failed: {e}", file=sys.stderr)
        return False

def filter_by_jobs(page):
    """Switch to Jobs filter."""
    print("[*] Filtering by Jobs", file=sys.stderr)
    try:
        jobs_btn = page.locator('button:has-text("Jobs"), a:has-text("Jobs"), [data-test="search-reusables__filter-pill-jobs"]').first
        jobs_btn.click()
        page.wait_for_timeout(2000)
        return True
    except Exception as e:
        print(f"[-] Jobs filter failed: {e}", file=sys.stderr)
        return False

def filter_by_date(page, hours=24):
    """Apply date posted filter."""
    print(f"[*] Filtering by last {hours} hours", file=sys.stderr)
    try:
        # Click date filter
        date_filter = page.locator('button:has-text("Date posted"), button:has-text("Date"), [aria-label*="Date"]').first
        date_filter.click()
        page.wait_for_timeout(1000)

        # Select past 24 hours
        option = page.locator('label:has-text("Past 24 hours"), li:has-text("Past 24 hours"), [data-test*="24"]').first
        option.click()
        page.wait_for_timeout(1000)

        # Click show results if available
        try:
            show_btn = page.locator('button:has-text("Show results"), button:has-text("Apply"), button:has-text("Done")').first
            show_btn.click(timeout=3000)
        except:
            pass

        page.wait_for_timeout(2000)
        return True
    except Exception as e:
        print(f"[-] Date filter failed: {e}", file=sys.stderr)
        return False

def scroll_page(page, max_scrolls=5):
    """Scroll page to load more content."""
    for i in range(max_scrolls):
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        page.wait_for_timeout(2000)
    print(f"[*] Scrolled {max_scrolls} times", file=sys.stderr)

def extract_posts(page):
    """Extract job-related posts from search results."""
    print("[*] Extracting posts", file=sys.stderr)
    posts = []

    try:
        # Get all post containers
        post_elements = page.locator('.feed-shared-update-v2, .occludable-update, .feed-shared-module').all()
        print(f"[*] Found {len(post_elements)} posts", file=sys.stderr)

        for i, post in enumerate(post_elements[:20]):
            try:
                text = post.inner_text(timeout=3000)
                link_el = post.locator('a[href*="/posts/"], a[href*="/update/"]').first

                # Check if post is job-related
                job_keywords = ['hiring', 'opening', 'vacancy', 'position', 'join', 'fresher',
                              'intern', 'trainee', 'junior', 'entry level', '0-1', '0-2', '1-2',
                              'immediate', 'urgent', 'required', 'looking for']

                if any(kw in text.lower() for kw in job_keywords):
                    post_url = ""
                    try:
                        post_url = link_el.get_attribute('href', timeout=2000)
                        if post_url and not post_url.startswith('http'):
                            post_url = f"https://www.linkedin.com{post_url}"
                    except:
                        pass

                    # Extract profile link
                    profile_url = ""
                    try:
                        profile_link = post.locator('a[href*="/in/"]').first
                        profile_url = profile_link.get_attribute('href', timeout=2000)
                    except:
                        pass

                    posts.append({
                        'type': 'post',
                        'text': text[:2000],
                        'url': post_url,
                        'profile': profile_url,
                        'index': i + 1
                    })
            except Exception as e:
                continue

    except Exception as e:
        print(f"[-] Post extraction error: {e}", file=sys.stderr)

    return posts

def extract_jobs(page):
    """Extract job listings from search results."""
    print("[*] Extracting jobs", file=sys.stderr)
    jobs = []

    try:
        # Get all job cards
        job_elements = page.locator('.job-card-container, .jobs-search-results__card, [data-view-name="job-card"], .job-card-list').all()
        print(f"[*] Found {len(job_elements)} job cards", file=sys.stderr)

        for i, job in enumerate(job_elements[:20]):
            try:
                text = job.inner_text(timeout=3000)

                # Get job link
                job_url = ""
                try:
                    link = job.locator('a[href*="/jobs/view/"]').first
                    job_url = link.get_attribute('href', timeout=2000)
                    if job_url and not job_url.startswith('http'):
                        job_url = f"https://www.linkedin.com{job_url}"
                except:
                    pass

                # Extract experience info
                experience_match = re.search(r'(\d+[\s-]*\d*\s*(?:year|yr|exp))', text.lower())
                exp_text = experience_match.group(1) if experience_match else "Not specified"

                # Check experience requirement - skip if > 2 years
                if experience_match:
                    years = re.findall(r'\d+', exp_text)
                    if years and max(int(y) for y in years) > 2:
                        continue

                jobs.append({
                    'type': 'job',
                    'text': text[:2000],
                    'url': job_url,
                    'experience': exp_text,
                    'index': i + 1
                })
            except Exception as e:
                continue

    except Exception as e:
        print(f"[-] Job extraction error: {e}", file=sys.stderr)

    return jobs

def format_results(posts, jobs, date_str):
    """Format results into structured output."""
    output = []
    output.append(f"LinkedIn Cybersecurity Jobs - {date_str}")
    output.append("=" * 50)
    output.append("")

    # Posts section
    output.append("PHASE 1: Posts (Last 24 Hours)")
    output.append("-" * 40)

    if posts:
        for i, post in enumerate(posts, 1):
            text = post['text']
            lines = text.split('\n')
            title_line = lines[0] if lines else "Unknown"

            output.append(f"\n{i}. {title_line[:80]}")
            if post.get('url'):
                output.append(f"   Post Link: {post['url']}")
            if post.get('profile'):
                output.append(f"   Profile: {post['profile']}")
            for line in lines[1:6]:
                if line.strip() and len(line.strip()) > 5:
                    output.append(f"   {line.strip()[:100]}")
    else:
        output.append("\nNo relevant posts found.")

    output.append("")

    # Jobs section
    output.append("PHASE 2: Jobs (Last 24 Hours)")
    output.append("-" * 40)

    if jobs:
        for i, job in enumerate(jobs, 1):
            text = job['text']
            lines = text.split('\n')
            title_line = lines[0] if lines else "Unknown"

            output.append(f"\n{i}. {title_line[:80]}")
            output.append(f"   Experience: {job.get('experience', 'Not specified')}")
            if job.get('url'):
                output.append(f"   Apply: {job['url']}")
            for line in lines[1:6]:
                if line.strip() and len(line.strip()) > 5:
                    output.append(f"   {line.strip()[:100]}")
    else:
        output.append("\nNo suitable jobs found.")

    output.append("")
    output.append("=" * 50)
    output.append(f"Summary:")
    output.append(f"Posts scanned: {len(posts)}")
    output.append(f"Jobs scanned: {len(jobs)}")
    output.append(f"Suitable positions: {len(jobs)}")

    return '\n'.join(output)

def run_setup():
    """First-time setup - open browser for manual LinkedIn login."""
    print("[*] Starting LinkedIn setup...", file=sys.stderr)
    print("[*] A browser window will open for LinkedIn login", file=sys.stderr)
    print("[*] Please login manually, then close the browser when done", file=sys.stderr)

    with sync_playwright() as p:
        # Launch in headed mode for manual login
        context = p.chromium.launch_persistent_context(
            user_data_dir=USER_DATA_DIR,
            headless=False,
            viewport={"width": 1280, "height": 800}
        )

        page = context.new_page()
        page.goto("https://www.linkedin.com/login", wait_until="domcontentloaded", timeout=60000)

        print("[*] Browser opened. Please login to LinkedIn.", file=sys.stderr)
        print("[*] After login, you can close the browser window.", file=sys.stderr)

        # Wait for user to close browser or login
        try:
            # Wait for navigation away from login page
            page.wait_for_url("**/feed/**", timeout=300000)
            print("[+] Login successful!", file=sys.stderr)
        except PlaywrightTimeout:
            # Check if we're logged in
            if "login" not in page.url:
                print("[+] Login appears successful", file=sys.stderr)
            else:
                print("[-] Login may have failed", file=sys.stderr)

        context.close()

    print(f"[+] Session saved to {USER_DATA_DIR}", file=sys.stderr)
    return True

def run_search():
    """Run the LinkedIn job search."""
    date_str = datetime.now().strftime("%Y-%m-%d")
    results_file = f"{RESULTS_DIR}/linkedin_jobs_{date_str}.txt"

    print("[*] LinkedIn Job Hunter starting...", file=sys.stderr)

    # Check if session exists
    if not check_session_exists():
        print("[-] No LinkedIn session found. Run with --setup first.", file=sys.stderr)
        print("[*] Example: python3 linkedin_job_hunter.py --setup", file=sys.stderr)
        return False

    with sync_playwright() as p:
        # Launch browser with persistent context
        context = p.chromium.launch_persistent_context(
            user_data_dir=USER_DATA_DIR,
            headless=True,
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled'
            ]
        )

        page = context.new_page()

        try:
            # Navigate to LinkedIn
            page.goto("https://www.linkedin.com/feed/", wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(3000)

            # Check if logged in
            if not verify_login(page):
                print("[-] Session expired. Run with --setup to re-login.", file=sys.stderr)
                context.close()
                return False

            print("[+] Logged in successfully", file=sys.stderr)

            # Phase 1: Search Posts
            print("\n[=== PHASE 1: Posts Search ===]", file=sys.stderr)
            if search_linkedin(page, SEARCH_QUERY):
                filter_by_posts(page)
                filter_by_date(page)
                scroll_page(page, max_scrolls=3)
                posts = extract_posts(page)
            else:
                posts = []

            # Phase 2: Search Jobs
            print("\n[=== PHASE 2: Jobs Search ===]", file=sys.stderr)
            if search_linkedin(page, SEARCH_QUERY):
                filter_by_jobs(page)
                filter_by_date(page)
                scroll_page(page, max_scrolls=5)
                jobs = extract_jobs(page)
            else:
                jobs = []

            # Format and output results
            results = format_results(posts, jobs, date_str)
            print(results)

            # Save to file
            with open(results_file, 'w') as f:
                f.write(results)
            print(f"\n[+] Results saved to {results_file}", file=sys.stderr)

            context.close()
            return True

        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            context.close()
            return False

def main():
    parser = argparse.ArgumentParser(description="LinkedIn Job Hunter")
    parser.add_argument('--setup', action='store_true', help='First-time setup for LinkedIn login')
    args = parser.parse_args()

    if args.setup:
        success = run_setup()
    else:
        success = run_search()

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
