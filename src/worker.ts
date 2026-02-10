import { Config, capTTL, ttlToVaultString, validateServiceExists } from './config';
import { encrypt } from './encryption';
import { RequestStore, BrokerRequest } from './requestStore';
import {
  fetchOIDCDiscovery,
  generatePKCE,
  buildAuthURL,
  exchangeCode,
} from './oidcDriver';
import { IPlaywrightDriver } from './playwrightDriver';
import { VaultClient } from './vaultClient';
import logger from './logger';

export class Worker {
  private config: Config;
  private store: RequestStore;
  private driver: IPlaywrightDriver;
  private vaultClient: VaultClient;

  constructor(
    config: Config,
    store: RequestStore,
    driver: IPlaywrightDriver,
    vaultClient: VaultClient,
  ) {
    this.config = config;
    this.store = store;
    this.driver = driver;
    this.vaultClient = vaultClient;
  }

  async processRequest(request: BrokerRequest): Promise<void> {
    const { id, service, wrap_ttl } = request;
    const startTime = Date.now();

    try {
      const serviceEntry = validateServiceExists(this.config, service);
      if (!serviceEntry) {
        this.store.fail(id, `Service '${service}' not found in registry`);
        return;
      }

      // Step 1: Headless OIDC login via Playwright
      logger.info('Starting headless OIDC login', { request_id: id, service });

      const discovery = await fetchOIDCDiscovery(this.config.keycloak.issuerURL);
      const pkce = generatePKCE();
      const authURL = buildAuthURL(
        discovery,
        this.config.keycloak.clientID,
        this.config.approver.redirectURI,
        pkce,
      );

      let loginResult;
      try {
        loginResult = await this.driver.login(
          authURL,
          this.config.approver.redirectURI,
          this.config.approver.username,
          this.config.approver.password,
          pkce.state,
        );
      } catch (err) {
        const msg = (err as Error).message;
        if (msg === 'DUO_DENIED' || msg.toLowerCase().includes('denied')) {
          this.store.deny(id, 'Duo push was denied by the approver');
          logger.info('Duo push denied', {
            request_id: id,
            elapsed_ms: Date.now() - startTime,
          });
          return;
        }
        throw err;
      }

      // Step 1b: Exchange authorization code for tokens
      logger.info('Exchanging authorization code', { request_id: id });
      const tokens = await exchangeCode(
        discovery,
        loginResult.code,
        this.config.keycloak.clientID,
        this.config.keycloak.clientSecret,
        this.config.approver.redirectURI,
        pkce.codeVerifier,
      );

      logger.info('OIDC token obtained, approval complete', { request_id: id });

      // Step 2: Read from Vault with response wrapping
      const effectiveTTLMs = capTTL(wrap_ttl, serviceEntry);
      const vaultTTL = ttlToVaultString(effectiveTTLMs);

      logger.info('Reading wrapped secret from Vault', {
        request_id: id,
        kv2_mount: serviceEntry.vault.kv2_mount,
        kv2_path: serviceEntry.vault.kv2_path,
        wrap_ttl: vaultTTL,
      });

      const wrapInfo = await this.vaultClient.readWrapped(
        serviceEntry.vault.kv2_mount,
        serviceEntry.vault.kv2_path,
        vaultTTL,
      );

      // Step 3: Encrypt wrap token and store as approved
      const encryptedToken = encrypt(wrapInfo.token, this.config.wrapTokenEncKey);
      const wrapExpiresAt = new Date(Date.now() + effectiveTTLMs).toISOString();

      this.store.approve(id, encryptedToken, wrapExpiresAt);

      const elapsed = Date.now() - startTime;
      logger.info('Request processing complete', {
        request_id: id,
        service,
        requester: request.requester,
        outcome: 'APPROVED',
        elapsed_ms: elapsed,
      });
    } catch (err) {
      const elapsed = Date.now() - startTime;
      const message = (err as Error).message;
      logger.error('Request processing failed', {
        request_id: id,
        service,
        requester: request.requester,
        outcome: 'FAILED',
        error: message,
        elapsed_ms: elapsed,
      });
      this.store.fail(id, message);
    }
  }
}
