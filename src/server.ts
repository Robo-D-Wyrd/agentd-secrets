import express from 'express';
import rateLimit from 'express-rate-limit';
import { loadConfig } from './config';
import { RequestStore } from './requestStore';
import { initJwtMiddleware } from './jwtMiddleware';
import { PlaywrightDriver } from './playwrightDriver';
import { VaultClient } from './vaultClient';
import { Worker } from './worker';
import { createApiRouter, createHealthRouter } from './routes';
import logger from './logger';

async function main() {
  logger.info('Starting x-pass broker');

  const config = loadConfig();

  // Initialize JWT middleware
  initJwtMiddleware(config.keycloak.issuerURL, config.keycloak.audience);

  // Initialize stores and clients
  const store = new RequestStore(config.wrapTokenEncKey);

  const playwrightDriver = new PlaywrightDriver({
    headless: config.playwright.headless,
    loginTimeout: config.approver.loginTimeout,
    duoTimeout: config.approver.duoTimeout,
  });

  const vaultClient = new VaultClient(
    config.vault.addr,
    config.vault.k8sAuthPath,
    config.vault.k8sRole,
    config.vault.k8sJWTPath,
  );

  const worker = new Worker(config, store, playwrightDriver, vaultClient);

  // Create Express app
  const app = express();
  app.use(express.json());

  // Rate limiting on POST /v1/requests
  const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later' },
    keyGenerator: (req) => req.ip || 'unknown',
  });
  app.use('/v1/requests', (req, _res, next) => {
    if (req.method === 'POST') {
      limiter(req, _res, next);
    } else {
      next();
    }
  });

  // Mount routes
  app.use(createHealthRouter(config, vaultClient));
  app.use(createApiRouter(config, store, worker));

  // Start server
  const server = app.listen(config.listenPort, () => {
    logger.info(`x-pass broker listening on ${config.listenAddr}`);
  });

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down`);
    store.shutdown();
    await playwrightDriver.close();
    server.close(() => {
      logger.info('Server closed');
      process.exit(0);
    });
    // Force exit after 10s
    setTimeout(() => process.exit(1), 10_000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  logger.error('Fatal startup error', { error: err.message, stack: err.stack });
  process.exit(1);
});
