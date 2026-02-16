import type { Browser, BrowserContext, Page } from 'playwright';
import logger from './logger';

export interface PlaywrightLoginResult {
  code: string;
  state: string;
}

export interface PlaywrightDriverOptions {
  headless: boolean;
  loginTimeout: number;
  duoTimeout: number;
}

export interface IPlaywrightDriver {
  login(
    authURL: string,
    redirectURI: string,
    username: string,
    password: string,
    expectedState: string,
  ): Promise<PlaywrightLoginResult>;
  close(): Promise<void>;
}

export class PlaywrightDriver implements IPlaywrightDriver {
  private browser: Browser | null = null;
  private options: PlaywrightDriverOptions;

  constructor(options: PlaywrightDriverOptions) {
    this.options = options;
  }

  private async ensureBrowser(): Promise<Browser> {
    if (!this.browser) {
      // Dynamic import to allow mocking in tests
      const pw = await import('playwright');
      this.browser = await pw.chromium.launch({
        headless: this.options.headless,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
        ],
      });
    }
    return this.browser;
  }

  async login(
    authURL: string,
    redirectURI: string,
    username: string,
    password: string,
    expectedState: string,
  ): Promise<PlaywrightLoginResult> {
    const startTime = Date.now();
    let context: BrowserContext | null = null;

    try {
      const browser = await this.ensureBrowser();
      context = await browser.newContext({
        ignoreHTTPSErrors: true,
      });
      const page = await context.newPage();

      // Navigate to authorization URL
      logger.info('Navigating to OIDC provider auth URL');
      await page.goto(authURL, { timeout: this.options.loginTimeout });

      // Fill in username and password on OIDC login form
      logger.info('Filling OIDC login form');
      await page.waitForSelector('#username', { timeout: this.options.loginTimeout });
      await page.fill('#username', username);
      await page.fill('#password', password);

      // Submit the form
      await page.click('#kc-login');

      // Wait for redirect to our callback URI.  After Keycloak submits
      // credentials, there may be intermediate pages (Duo MFA iframe,
      // consent screens, "continue" buttons).  We poll the page
      // periodically, clicking through known interstitials, until the
      // final redirect arrives or the timeout expires.
      logger.info('Waiting for Duo approval (push notification)');

      const redirectPrefix = redirectURI.split('?')[0];
      let redirectUrl: string | null = null;
      const deadline = Date.now() + this.options.duoTimeout;

      while (Date.now() < deadline) {
        const currentUrl = page.url();

        // Check if we've arrived at the callback URI
        if (currentUrl.startsWith(redirectPrefix)) {
          redirectUrl = currentUrl;
          break;
        }

        // Log where we are periodically for diagnostics
        logger.debug('Waiting for redirect', { currentUrl });

        // --- Handle known interstitial pages ---

        // Duo Universal Prompt "Trust this browser?" / "Yes, trust" button
        const trustBtn = await page.$('button#trust-browser-button, button:has-text("Yes, trust")').catch(() => null);
        if (trustBtn) {
          logger.info('Clicking Duo "Trust browser" button');
          await trustBtn.click().catch(() => {});
        }

        // Keycloak consent / continue screens
        const consentBtn = await page.$('#kc-login, #kc-accept, input[type="submit"][value="Yes"], button:has-text("Continue")').catch(() => null);
        if (consentBtn) {
          const btnText = await consentBtn.textContent().catch(() => '');
          logger.info('Clicking consent/continue button', { text: btnText });
          await consentBtn.click().catch(() => {});
        }

        // Check for OIDC error on current page
        if (currentUrl.includes('error=')) {
          const urlObj = new URL(currentUrl);
          const error = urlObj.searchParams.get('error');
          const desc = urlObj.searchParams.get('error_description');
          throw new Error(`OIDC auth error: ${error} - ${desc}`);
        }

        // Check for Keycloak error messages
        const errorEl = await page.$('.alert-error, .kc-feedback-text').catch(() => null);
        if (errorEl) {
          const errorText = await errorEl.textContent();
          if (errorText?.toLowerCase().includes('denied') ||
              errorText?.toLowerCase().includes('rejected')) {
            throw new Error('DUO_DENIED');
          }
          if (errorText?.toLowerCase().includes('invalid') ||
              errorText?.toLowerCase().includes('expired')) {
            throw new Error(`OIDC login error: ${errorText}`);
          }
        }

        // Poll every 2 seconds
        await page.waitForTimeout(2000);
      }

      if (!redirectUrl) {
        const finalUrl = page.url();
        const pageTitle = await page.title().catch(() => '');
        logger.error('Login timed out', { finalUrl, pageTitle });
        throw new Error(
          `Login timed out after ${this.options.duoTimeout}ms (page: ${finalUrl})`
        );
      }

      // Parse the redirect URL for code and state
      const parsed = new URL(redirectUrl);
      const code = parsed.searchParams.get('code');
      const state = parsed.searchParams.get('state');

      if (!code) {
        const error = parsed.searchParams.get('error');
        if (error) {
          throw new Error(`OIDC error: ${error}`);
        }
        throw new Error('No authorization code in redirect');
      }

      if (state !== expectedState) {
        throw new Error('State mismatch in OIDC redirect');
      }

      const elapsed = Date.now() - startTime;
      logger.info('Headless login completed', { elapsed_ms: elapsed });

      return { code, state };
    } finally {
      if (context) {
        await context.close().catch(() => {});
      }
    }
  }

  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close().catch(() => {});
      this.browser = null;
    }
  }
}
