import { v4 as uuidv4 } from 'uuid';
import { encrypt, decrypt } from './encryption';
import logger from './logger';

export type RequestStatus = 'PENDING_APPROVAL' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'FAILED';

export interface BrokerRequest {
  id: string;
  service: string;
  reason: string;
  requester: string;
  wrap_ttl: string;
  status: RequestStatus;
  created_at: string;
  expires_at: string;
  encrypted_wrap_token?: Buffer;
  wrap_expires_at?: string;
  failure_reason?: string;
}

export interface RequestPublicView {
  request_id: string;
  service: string;
  requester: string;
  status: RequestStatus;
  created_at: string;
  wrap_token?: string;
  wrap_expires_at?: string;
  failure_reason?: string;
}

const REQUEST_LIFETIME_MS = 15 * 60 * 1000;

export class RequestStore {
  private requests = new Map<string, BrokerRequest>();
  private encKey: Buffer;
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor(encKey: Buffer) {
    this.encKey = encKey;
    this.cleanupInterval = setInterval(() => this.expireRequests(), 30_000);
  }

  create(service: string, reason: string, requester: string, wrapTTL: string): BrokerRequest {
    const id = uuidv4();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + REQUEST_LIFETIME_MS);

    const request: BrokerRequest = {
      id,
      service,
      reason,
      requester,
      wrap_ttl: wrapTTL,
      status: 'PENDING_APPROVAL',
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };

    this.requests.set(id, request);
    logger.info('Request created', { request_id: id, service, requester });
    return request;
  }

  get(id: string): BrokerRequest | undefined {
    const req = this.requests.get(id);
    if (req && req.status === 'PENDING_APPROVAL') {
      if (new Date(req.expires_at) < new Date()) {
        req.status = 'EXPIRED';
      }
    }
    return req;
  }

  approve(id: string, encryptedWrapToken: Buffer, wrapExpiresAt: string): void {
    const req = this.requests.get(id);
    if (!req) throw new Error(`Request ${id} not found`);
    if (req.status !== 'PENDING_APPROVAL') throw new Error(`Request ${id} not in PENDING_APPROVAL`);
    req.status = 'APPROVED';
    req.encrypted_wrap_token = encryptedWrapToken;
    req.wrap_expires_at = wrapExpiresAt;
    logger.info('Request approved', { request_id: id, service: req.service });
  }

  deny(id: string, reason?: string): void {
    const req = this.requests.get(id);
    if (!req) throw new Error(`Request ${id} not found`);
    req.status = 'DENIED';
    req.failure_reason = reason || 'Duo approval denied';
    logger.info('Request denied', { request_id: id, service: req.service });
  }

  fail(id: string, reason: string): void {
    const req = this.requests.get(id);
    if (!req) throw new Error(`Request ${id} not found`);
    req.status = 'FAILED';
    req.failure_reason = reason;
    logger.warn('Request failed', { request_id: id, service: req.service, reason });
  }

  toPublicView(req: BrokerRequest): RequestPublicView {
    const view: RequestPublicView = {
      request_id: req.id,
      service: req.service,
      requester: req.requester,
      status: req.status,
      created_at: req.created_at,
    };

    if (req.status === 'APPROVED' && req.encrypted_wrap_token) {
      view.wrap_token = decrypt(req.encrypted_wrap_token, this.encKey);
      view.wrap_expires_at = req.wrap_expires_at;
    }

    if (req.failure_reason) {
      view.failure_reason = req.failure_reason;
    }

    return view;
  }

  private expireRequests(): void {
    const now = new Date();
    for (const [id, req] of this.requests) {
      if (req.status === 'PENDING_APPROVAL' && new Date(req.expires_at) < now) {
        req.status = 'EXPIRED';
        logger.info('Request expired', { request_id: id });
      }
      // Cleanup very old requests (>1h) to prevent memory leak
      const ageMs = now.getTime() - new Date(req.created_at).getTime();
      if (ageMs > 3600_000) {
        this.requests.delete(id);
      }
    }
  }

  shutdown(): void {
    clearInterval(this.cleanupInterval);
  }
}
