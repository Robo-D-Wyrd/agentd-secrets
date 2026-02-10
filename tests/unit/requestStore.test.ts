import crypto from 'crypto';
import { RequestStore } from '../../src/requestStore';
import { encrypt } from '../../src/encryption';

describe('RequestStore', () => {
  const key = crypto.randomBytes(32);
  let store: RequestStore;

  beforeEach(() => {
    store = new RequestStore(key);
  });

  afterEach(() => {
    store.shutdown();
  });

  test('create returns a request with PENDING_APPROVAL status', () => {
    const req = store.create('payroll-db', 'Need creds for deployment', 'bot-1', '5m');
    expect(req.id).toBeDefined();
    expect(req.status).toBe('PENDING_APPROVAL');
    expect(req.service).toBe('payroll-db');
    expect(req.reason).toBe('Need creds for deployment');
    expect(req.requester).toBe('bot-1');
  });

  test('create generates UUIDv4 ids', () => {
    const req = store.create('svc', 'test', 'bot', '5m');
    // UUIDv4 format
    expect(req.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  test('get returns stored request', () => {
    const created = store.create('svc', 'test', 'bot', '5m');
    const fetched = store.get(created.id);
    expect(fetched).toBeDefined();
    expect(fetched!.id).toBe(created.id);
  });

  test('get returns undefined for unknown id', () => {
    expect(store.get('nonexistent-id')).toBeUndefined();
  });

  test('approve transitions to APPROVED', () => {
    const req = store.create('svc', 'test', 'bot', '5m');
    const encToken = encrypt('hvs.test-token', key);
    store.approve(req.id, encToken, new Date(Date.now() + 300_000).toISOString());
    const updated = store.get(req.id);
    expect(updated!.status).toBe('APPROVED');
    expect(updated!.encrypted_wrap_token).toBeDefined();
  });

  test('deny transitions to DENIED', () => {
    const req = store.create('svc', 'test', 'bot', '5m');
    store.deny(req.id, 'Push rejected');
    const updated = store.get(req.id);
    expect(updated!.status).toBe('DENIED');
    expect(updated!.failure_reason).toBe('Push rejected');
  });

  test('fail transitions to FAILED', () => {
    const req = store.create('svc', 'test', 'bot', '5m');
    store.fail(req.id, 'Vault unreachable');
    const updated = store.get(req.id);
    expect(updated!.status).toBe('FAILED');
    expect(updated!.failure_reason).toBe('Vault unreachable');
  });

  test('approve throws on non-pending request', () => {
    const req = store.create('svc', 'test', 'bot', '5m');
    store.deny(req.id);
    const encToken = encrypt('token', key);
    expect(() => store.approve(req.id, encToken, new Date().toISOString())).toThrow('not in PENDING_APPROVAL');
  });

  test('toPublicView decrypts wrap token for APPROVED', () => {
    const req = store.create('svc', 'test', 'bot', '5m');
    const wrapToken = 'hvs.my-wrap-token';
    const encToken = encrypt(wrapToken, key);
    const expiresAt = new Date(Date.now() + 300_000).toISOString();
    store.approve(req.id, encToken, expiresAt);

    const view = store.toPublicView(store.get(req.id)!);
    expect(view.status).toBe('APPROVED');
    expect(view.wrap_token).toBe(wrapToken);
    expect(view.wrap_expires_at).toBe(expiresAt);
  });

  test('toPublicView does not include wrap_token for non-APPROVED', () => {
    const req = store.create('svc', 'test', 'bot', '5m');
    const view = store.toPublicView(store.get(req.id)!);
    expect(view.status).toBe('PENDING_APPROVAL');
    expect(view.wrap_token).toBeUndefined();
  });
});
