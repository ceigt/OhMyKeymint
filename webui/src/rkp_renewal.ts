export interface RkpRenewalStatus {
  enabled: boolean
  worker_running: boolean
  protocol: string | null
  last_successful_protocol: string | null
  expires_at: number | null
  last_check: number
  last_success: number
  next_check: number
  blocked: string | null
  pending: boolean
  recovery_required: boolean
  issuance_stage: string
  last_error: { code: string, stage: string, at: number, retry_at: number | null } | null
}
const protocols = ['v1', 'v2', 'v1-native']
export function parseRkpRenewalStatus(value: unknown): RkpRenewalStatus {
  const fields = ['worker_running', 'last_error', 'enabled', 'protocol', 'last_successful_protocol', 'expires_at', 'last_check', 'last_success', 'next_check', 'blocked', 'pending', 'recovery_required', 'issuance_stage']
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid renewal status')
  const v = value as Record<string, unknown>
  if (Object.keys(v).length !== fields.length || Object.keys(v).some(k => !fields.includes(k))
    || ['enabled', 'worker_running', 'pending', 'recovery_required'].some(k => typeof v[k] !== 'boolean')
    || ['protocol', 'last_successful_protocol'].some(k => v[k] !== null && !protocols.includes(v[k] as string))
    || ['last_check', 'last_success', 'next_check'].some(k => !Number.isSafeInteger(v[k]) || (v[k] as number) < 0)
    || (v.expires_at !== null && (!Number.isSafeInteger(v.expires_at) || (v.expires_at as number) < 0))
    || (v.blocked !== null && (typeof v.blocked !== 'string' || v.blocked.length > 512 || /[\x00-\x1f]/.test(v.blocked)))
    || typeof v.issuance_stage !== 'string' || !['', 'preparing', 'submitted', 'completed', 'acknowledged'].includes(v.issuance_stage)) throw new Error('Invalid renewal status')
  if (v.last_error !== null) {
    const e = v.last_error as Record<string, unknown>
    if (!e || typeof e !== 'object' || Array.isArray(e) || Object.keys(e).sort().join(',') !== 'at,code,retry_at,stage'
      || !['revocation_network', 'submission_uncertain', 'pre_submission', 'storage_unavailable', 'interface_unavailable', 'challenge_network', 'csr_failed', 'local_state', 'configuration_changed', 'candidate_invalid', 'active_changed', 'load_unconfirmed', 'rollback_unconfirmed'].includes(e.code as string)
      || !['validation', 'submission', 'preparation', 'recovery', 'replacement', 'confirmation'].includes(e.stage as string)
      || !Number.isSafeInteger(e.at) || (e.at as number) < 0
      || (e.retry_at !== null && (!Number.isSafeInteger(e.retry_at) || (e.retry_at as number) < 0))) throw new Error('Invalid renewal failure')
  }
  return value as RkpRenewalStatus
}
