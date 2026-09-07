---
description: Run the LinkedIn Job Hunter agent to search for cybersecurity fresher positions
agent: linkedinjobhunter
---

# LinkedIn Job Hunter Command

Run the LinkedIn Job Hunter agent to search for cybersecurity fresher positions.

## Usage

Simply run this command to start the job hunt:

```
/linkedinjobhunt
```

The agent will:
1. Run the Playwright-based LinkedIn scraper
2. Search LinkedIn Posts for the last 24 hours
3. Search LinkedIn Jobs for the last 24 hours
4. Filter for fresher/junior positions (0-2 years experience)
5. Send results to Telegram
6. Save backup copy to `/tmp/`

## Notes

- Uses Playwright for headless browser automation
- No remote debugging permission required
- Persistent browser session (login once, reuse forever)
- Bot Token: 8877196896:AAFqicCBd5LyYS_I9rx1IQLwrRztU6iRCbA
- Chat ID: 8049550175
- Results saved to `/tmp/linkedin_jobs_[DATE].txt`
