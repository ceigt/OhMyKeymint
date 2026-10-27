export interface RkpRenewalStatus {
  enabled: boolean
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
}
const protocols = ['v1', 'v2', 'v1-native']
export function parseRkpRenewalStatus(value: unknown): RkpRenewalStatus {
  const fields = ['enabled', 'protocol', 'last_successful_protocol', 'expires_at', 'last_check', 'last_success', 'next_check', 'blocked', 'pending', 'recovery_required', 'issuance_stage']
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid renewal status')
  const v = value as Record<string, unknown>
  if (Object.keys(v).length !== fields.length || Object.keys(v).some(k => !fields.includes(k))
    || ['enabled', 'pending', 'recovery_required'].some(k => typeof v[k] !== 'boolean')
    || ['protocol', 'last_successful_protocol'].some(k => v[k] !== null && !protocols.includes(v[k] as string))
    || ['last_check', 'last_success', 'next_check'].some(k => !Number.isSafeInteger(v[k]) || (v[k] as number) < 0)
    || (v.expires_at !== null && (!Number.isSafeInteger(v.expires_at) || (v.expires_at as number) < 0))
    || (v.blocked !== null && (typeof v.blocked !== 'string' || v.blocked.length > 512 || /[\x00-\x1f]/.test(v.blocked)))
    || typeof v.issuance_stage !== 'string' || !['', 'preparing', 'submitted', 'completed', 'acknowledged'].includes(v.issuance_stage)) throw new Error('Invalid renewal status')
  return value as RkpRenewalStatus
}
