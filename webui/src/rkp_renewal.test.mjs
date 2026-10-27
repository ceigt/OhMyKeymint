import assert from 'node:assert/strict'
import { parseRkpRenewalStatus } from './rkp_renewal.ts'
const status = { enabled: false, worker_running: false, last_error: null, protocol: null, last_successful_protocol: 'v1', expires_at: 1793932023, last_check: 0, last_success: 0, next_check: 0, blocked: null, pending: false, recovery_required: false, issuance_stage: '' }
assert.deepEqual(parseRkpRenewalStatus(status), status)
for (const change of [{ enabled: 1 }, { protocol: 'auto' }, { blocked: 'bad\nvalue' }, { extra: 'secret' }, { last_check: -1 }, { expires_at: Number.MAX_SAFE_INTEGER + 1 }]) {
  assert.throws(() => parseRkpRenewalStatus({ ...status, ...change }))
}
assert.throws(() => parseRkpRenewalStatus({}))
const failure = {code:'revocation_network', stage:'validation', at:10, retry_at:20}
assert.deepEqual(parseRkpRenewalStatus({...status,last_error:failure}).last_error, failure)
for (const change of [{code:'private key'}, {stage:'secret'}, {at:-1}, {retry_at:-1}, {extra:1}]) assert.throws(() => parseRkpRenewalStatus({...status,last_error:{...failure,...change}}))
console.log('Renewal status parser checks passed')
