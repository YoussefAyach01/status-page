# BUSINESS: status-page

**Buyer:** small SaaS teams, agencies and freelancers who want a public "are you down?" page and basic uptime history without paying Statuspage/Better Stack prices; Moroccan/MENA web agencies who want to add it to maintenance retainers.
**Problem:** clients ask "is the site down?" and there is no simple proof of uptime. Existing tools are USD-priced and overkill for 3-5 endpoints.

## Pricing

| Plan                                                                                   | Pages | Monitors | Interval | MAD | USD |
| -------------------------------------------------------------------------------------- | ----- | -------- | -------- | --- | --- |
| Free                                                                                   | 1     | 5        | 5 min    | 0   | 0   |
| Pro                                                                                    | 10    | 50       | 1 min    | 99  | 10  |
| Agency pack (white-label, custom domain): 349 MAD / 35 USD, once custom domains exist. |

## First 5 customers

1. Offer it as a value-add to existing website clients/agencies (send them a demo page with their own site monitored for free for 30 days).
2. Post in indie hacker / r/selfhosted / dev.to as "free status page, 5 monitors, no signup wall" and collect emails for the Pro upsell.
3. Approach 10 Moroccan startups and e-commerce shops on LinkedIn with a screenshot of their own site's status page as the cold-message hook.

## Accounts needed to go live

Host with a persistent disk + domain; payment provider (Paddle/LemonSqueezy/Stripe entity); Resend or Telegram bot for down alerts (alerts are the feature buyers expect, and are NOT built yet); optionally a second checker region.

## Honest limits

- Alerts are the main missing piece; without them it is a page, not a monitoring product.
- Single-region checks, SQLite on one box: fine for hundreds of monitors, not thousands.
- Crowded market (UptimeRobot free, Better Stack, Instatus). Compete on local pricing, agency white-label, simplicity.
