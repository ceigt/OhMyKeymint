<script setup lang="ts">
import { ref, shallowRef, watch } from 'vue'
import { MiuixDialog, MiuixButton, MiuixRadioButtonPreference } from 'miuix-vue'
import type { Cli } from '../cli'
import type { RkpRenewalStatus } from '../rkp_renewal'
import { i18n } from '../i18n'
const props = defineProps<{ modelValue: boolean, cli: Cli }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean], notify: [message: string, error?: boolean] }>()
const state = shallowRef<RkpRenewalStatus | null>(null)
const busy = ref(false)
const error = ref('')
const protocol = ref('last-success')
const protocols = ['last-success', 'v1', 'v2', 'v1-native']
type Action = 'enable' | 'disable' | 'resume' | 'recover' | 'discard' | 'status'
const confirmation = ref<Action | null>(null)
function label(p: string): string {
  return p === 'last-success' ? i18n.t('rkp_renewal_last_success') : i18n.t(`rkp_protocol_${p}`)
}
function date(t: number | null): string { return t ? new Date(t * 1000).toLocaleString() : i18n.t('rkp_renewal_unknown') }
async function run(action: Action): Promise<void> {
  if (busy.value) return
  busy.value = true; error.value = ''
  try {
    state.value = await props.cli.rkpRenewal(action, protocol.value)
    confirmation.value = null
    if (action !== 'status') emit('notify', i18n.t('rkp_renewal_updated'))
  } catch (e) { error.value = e instanceof Error ? e.message : String(e) }
  finally { busy.value = false }
}
watch(() => props.modelValue, open => { if (open) { state.value = null; confirmation.value = null; void run('status') } })
</script>
<template>
  <MiuixDialog :model-value="modelValue" :title="i18n.t('rkp_renewal_title')" :close-on-click-modal="!busy && !confirmation" @update:model-value="value => { if (!busy && !confirmation) emit('update:modelValue', value) }">
    <div class="confirm-sheet" :aria-busy="busy">
      <p>{{ i18n.t('rkp_renewal_description') }}</p>
      <template v-if="state">
        <p>{{ i18n.t('rkp_renewal_state') }}: {{ i18n.t(state.enabled ? 'rkp_renewal_enabled' : 'rkp_renewal_disabled') }}</p>
        <p v-if="state.enabled">{{ i18n.t(state.worker_running ? 'rkp_renewal_worker_running' : 'rkp_renewal_worker_stopped') }}</p>
        <p v-if="state.last_error" role="alert">{{ i18n.t(`rkp_error_${state.last_error.code}`) }} · {{ date(state.last_error.at) }}<template v-if="state.last_error.retry_at"> · {{ i18n.t('rkp_renewal_next_retry') }}: {{ date(state.last_error.retry_at) }}</template></p>
        <p v-if="state.protocol">{{ i18n.t('rkp_protocol') }}: {{ label(state.protocol) }}</p>
        <p>{{ i18n.t('rkp_renewal_expiry') }}: {{ date(state.expires_at) }}</p>
        <p>{{ i18n.t('rkp_renewal_last_check') }}: {{ date(state.last_check) }}</p>
        <p>{{ i18n.t('rkp_renewal_last_completed') }}: {{ date(state.last_success) }}</p>
        <p v-if="state.blocked" role="alert">{{ state.blocked }}</p>
        <p v-if="state.pending">{{ i18n.t('rkp_renewal_pending') }}</p>
        <p v-if="state.issuance_stage === 'submitted'" role="alert">{{ i18n.t('rkp_renewal_uncertain') }}</p>
        <p>{{ i18n.t('rkp_renewal_last_success') }}: {{ state.last_successful_protocol ? label(state.last_successful_protocol) : i18n.t('rkp_renewal_unknown') }}</p>
        <div role="radiogroup" :aria-label="i18n.t('rkp_protocol')">
          <MiuixRadioButtonPreference v-for="p in protocols" :key="p" :model-value="protocol === p" :title="label(p)" :disabled="busy || state.enabled || (p === 'last-success' && !state.last_successful_protocol)" @select="protocol = p" />
        </div>
      </template>
      <p v-if="error" role="alert">{{ error }}</p>
      <div class="confirm-sheet__actions">
        <MiuixButton :disabled="busy" @click="run('status')">{{ i18n.t('rkp_refresh_list') }}</MiuixButton>
        <MiuixButton v-if="state?.enabled" :disabled="busy" @click="run('disable')">{{ i18n.t('rkp_renewal_disable') }}</MiuixButton>
        <MiuixButton v-else type="primary" :disabled="busy || !state || (protocol === 'last-success' && !state.last_successful_protocol)" @click="confirmation = 'enable'">{{ i18n.t('rkp_renewal_enable') }}</MiuixButton>
      </div>
      <div class="confirm-sheet__actions">
        <MiuixButton v-if="state?.recovery_required" :disabled="busy" @click="confirmation = 'recover'">{{ i18n.t('rkp_renewal_recover') }}</MiuixButton>
        <MiuixButton v-if="state?.blocked || state?.issuance_stage === 'submitted'" :disabled="busy" @click="confirmation = 'resume'">{{ i18n.t('rkp_renewal_resume') }}</MiuixButton>
        <MiuixButton v-if="state?.pending && !state.recovery_required" :disabled="busy" @click="confirmation = 'discard'">{{ i18n.t('rkp_renewal_discard') }}</MiuixButton>
        <MiuixButton :disabled="busy" @click="emit('update:modelValue', false)">{{ i18n.t('cancel') }}</MiuixButton>
      </div>
    </div>
  </MiuixDialog>
  <MiuixDialog :model-value="confirmation !== null" :title="i18n.t('rkp_renewal_confirm')" :close-on-click-modal="!busy" @update:model-value="value => { if (!value && !busy) confirmation = null }">
    <div class="confirm-sheet">
      <p>{{ i18n.t(confirmation === 'enable' ? 'rkp_renewal_warning' : confirmation === 'resume' ? 'rkp_renewal_resume_warning' : confirmation === 'recover' ? 'rkp_renewal_recover_warning' : 'rkp_renewal_discard_warning') }}</p>
      <p v-if="error" role="alert">{{ error }}</p>
      <div class="confirm-sheet__actions">
        <MiuixButton :disabled="busy" @click="confirmation = null">{{ i18n.t('cancel') }}</MiuixButton>
        <MiuixButton type="primary" :disabled="busy" @click="confirmation && run(confirmation)">{{ i18n.t('rkp_renewal_confirm') }}</MiuixButton>
      </div>
    </div>
  </MiuixDialog>
</template>
