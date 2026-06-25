<script setup>
import { ref, reactive, nextTick } from 'vue'

const API = '/api'
const activeTab = ref('pentest')

// ======== Alert / Pentest Form ========
const alertInput = ref('')
const pentestTarget = ref('')
const threadId = ref('default')
const loading = ref(false)
const result = ref(null) // { analysis, response_plan, report, analysis_id, task_type }

// ======== Streaming ========
const streaming = ref(false)
const streamLabels = reactive([]) // [{label, status, node}]

// ======== Chat ========
const chatThreadId = ref('default')
const chatMsg = ref('')
const chatLoading = ref(false)
const chatReply = ref(null)
const chatAgent = ref('')

// ======== History ========
const history = ref([])

// ======== Helpers ========
function api(path, opts = {}) {
  return fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  }).then(r => r.ok ? r.json() : r.text().then(t => { throw new Error(t) }))
}

async function loadHistory() {
  try { history.value = await api('/analyses') } catch {}
}

async function runAnalysis() {
  if (!alertInput.value.trim()) return
  loading.value = true; result.value = null
  try {
    result.value = await api('/analyze', {
      method: 'POST',
      body: JSON.stringify({ alert_data: alertInput.value, task_type: 'alert', thread_id: threadId.value }),
    })
  } catch (e) { result.value = { error: e.message } }
  loading.value = false
  loadHistory()
}

async function runPentest() {
  if (!pentestTarget.value.trim()) return
  loading.value = true; result.value = null
  try {
    result.value = await api('/pentest', {
      method: 'POST',
      body: JSON.stringify({ target: pentestTarget.value, task_type: 'pentest', thread_id: threadId.value }),
    })
  } catch (e) { result.value = { error: e.message } }
  loading.value = false
  loadHistory()
}

async function runStream(mode) {
  const input = mode === 'pentest' ? pentestTarget.value : alertInput.value
  if (!input.trim()) return
  streaming.value = true; result.value = null
  streamLabels.splice(0, streamLabels.length)

  const body = mode === 'pentest'
    ? JSON.stringify({ target: input, task_type: 'pentest', thread_id: threadId.value })
    : JSON.stringify({ alert_data: input, task_type: 'alert', thread_id: threadId.value })

  try {
    const resp = await fetch(`${API}/${mode}/stream`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
    })
    const reader = resp.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() || ''
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.slice(6))
            streamLabels.push(data)
            if (data.node === 'done') {
              result.value = {
                analysis: data.analysis,
                response_plan: data.response_plan,
                report: data.report,
                analysis_id: data.analysis_id,
                task_type: mode,
              }
            }
            await nextTick()
          } catch {}
        }
      }
    }
  } catch (e) { result.value = { error: e.message } }
  streaming.value = false
  loadHistory()
}

async function sendChat() {
  if (!chatMsg.value.trim()) return
  chatLoading.value = true; chatReply.value = null
  try {
    const resp = await api(`/chat/${chatThreadId.value}`, {
      method: 'POST',
      body: JSON.stringify({ message: chatMsg.value }),
    })
    chatReply.value = resp.reply
    chatAgent.value = resp.routed_to_agent || ''
  } catch (e) { chatReply.value = 'Error: ' + e.message }
  chatLoading.value = false
}

function fmt(s) {
  if (!s) return ''
  return s.replace(/^### /gm, '').replace(/\*\*(.*?)\*\*/g, '$1')
}

loadHistory()
</script>

<template>
<div style="max-width:1100px;margin:0 auto;padding:16px">

  <!-- Header -->
  <div style="text-align:center;padding:24px 0">
    <h1 style="font-size:1.5em;background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent">
      Security Agent — 多智能体安全分析系统
    </h1>
    <p style="color:#94a3b8;font-size:0.85em;margin-top:4px">LangGraph + MCP | 4 Agent · 3 MCP Server</p>
  </div>

  <!-- Tabs -->
  <div style="display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #1e293b;padding-bottom:0">
    <button v-for="t in [
      {k:'pentest',label:'💣 渗透测试'},{k:'analyze',label:'🔍 告警分析'},
      {k:'chat',label:'💬 追问'},{k:'history',label:'📋 历史'}
    ]" :key="t.k"
      @click="activeTab=t.k"
      :style="{
        padding:'8px 18px',border:'none',cursor:'pointer',fontSize:'0.88em',
        background: activeTab===t.k ? 'rgba(56,189,248,0.1)' : 'transparent',
        color: activeTab===t.k ? '#38bdf8' : '#94a3b8',
        borderBottom: activeTab===t.k ? '2px solid #38bdf8' : '2px solid transparent',
        transition:'all .2s'
      }"
    >{{ t.label }}</button>
  </div>

  <!-- ====== PENTEST ====== -->
  <div v-if="activeTab==='pentest'" style="display:flex;flex-direction:column;gap:12px">
    <label style="font-size:0.85em;color:#94a3b8">目标 IP / 域名</label>
    <input v-model="pentestTarget" @keyup.enter="runStream('pentest')"
      placeholder="例如: 192.168.1.1 或 example.com"
      style="padding:10px 14px;border-radius:8px;border:1px solid #334155;background:#111827;color:#e2e8f0;font-size:0.92em;outline:none"
    />
    <div style="display:flex;gap:8px">
      <button @click="runStream('pentest')" :disabled="streaming"
        style="padding:8px 20px;border-radius:6px;border:none;background:#2dd4bf;color:#0b1120;font-weight:600;cursor:pointer;font-size:0.88em"
      >🚀 流式扫描</button>
      <button @click="runPentest" :disabled="loading"
        style="padding:8px 20px;border-radius:6px;border:1px solid #334155;background:transparent;color:#94a3b8;cursor:pointer;font-size:0.88em"
      >一次性返回</button>
    </div>
  </div>

  <!-- ====== ANALYZE ====== -->
  <div v-if="activeTab==='analyze'" style="display:flex;flex-direction:column;gap:12px">
    <label style="font-size:0.85em;color:#94a3b8">安全告警内容</label>
    <textarea v-model="alertInput" rows="3"
      placeholder="例如: 检测到来自 45.33.32.156 的异常登录行为，凌晨3点，尝试了5个账户"
      style="padding:10px 14px;border-radius:8px;border:1px solid #334155;background:#111827;color:#e2e8f0;font-size:0.92em;outline:none;resize:vertical"
    ></textarea>
    <div style="display:flex;gap:8px">
      <button @click="runStream('analyze')" :disabled="streaming"
        style="padding:8px 20px;border-radius:6px;border:none;background:#818cf8;color:#fff;font-weight:600;cursor:pointer;font-size:0.88em"
      >🚀 流式分析</button>
      <button @click="runAnalysis" :disabled="loading"
        style="padding:8px 20px;border-radius:6px;border:1px solid #334155;background:transparent;color:#94a3b8;cursor:pointer;font-size:0.88em"
      >一次性返回</button>
    </div>
  </div>

  <!-- ====== CHAT ====== -->
  <div v-if="activeTab==='chat'" style="display:flex;flex-direction:column;gap:12px">
    <div style="display:flex;gap:8px;align-items:center">
      <label style="font-size:0.85em;color:#94a3b8;white-space:nowrap">Thread ID:</label>
      <input v-model="chatThreadId"
        style="flex:1;padding:8px 12px;border-radius:6px;border:1px solid #334155;background:#111827;color:#e2e8f0;font-size:0.88em"
      />
    </div>
    <input v-model="chatMsg" @keyup.enter="sendChat"
      placeholder="追问: 这个 IP 有没有关联的恶意域名？"
      style="padding:10px 14px;border-radius:8px;border:1px solid #334155;background:#111827;color:#e2e8f0;font-size:0.92em;outline:none"
    />
    <button @click="sendChat" :disabled="chatLoading"
      style="padding:8px 20px;border-radius:6px;border:none;background:#fbbf24;color:#0b1120;font-weight:600;cursor:pointer;font-size:0.88em;align-self:flex-start"
    >💬 发送追问</button>
    <div v-if="chatLoading" style="color:#fbbf24;font-size:0.85em">Agent 正在回答...</div>
    <div v-if="chatReply" style="background:#111827;border:1px solid #1e293b;border-radius:8px;padding:16px;margin-top:8px">
      <div v-if="chatAgent" style="font-size:0.75em;color:#38bdf8;margin-bottom:6px">→ 路由到: {{ chatAgent }}</div>
      <pre style="white-space:pre-wrap;font-size:0.85em;color:#e2e8f0;line-height:1.7;font-family:inherit">{{ chatReply }}</pre>
    </div>
  </div>

  <!-- ====== HISTORY ====== -->
  <div v-if="activeTab==='history'">
    <button @click="loadHistory" style="padding:6px 14px;border-radius:6px;border:1px solid #334155;background:transparent;color:#94a3b8;cursor:pointer;font-size:0.85em;margin-bottom:12px">🔄 刷新</button>
    <div v-if="history.length===0" style="color:#94a3b8;font-size:0.85em">暂无记录</div>
    <div v-for="r in history" :key="r.id"
      style="padding:10px 14px;border:1px solid #1e293b;border-radius:8px;margin-bottom:8px;cursor:pointer"
      @click="async ()=>{ try { result.value = await api('/analyses/'+r.id) } catch {} }">
      <span style="font-size:0.82em;color:#94a3b8">#{{ r.id }} [{{ r.task_type }}] {{ r.input_data?.slice(0,60) }}...</span>
      <span style="float:right;font-size:0.75em;color:#64748b">{{ r.created_at }}</span>
    </div>
  </div>

  <!-- ====== Streaming Progress ====== -->
  <div v-if="streamLabels.length>0 && streaming" style="margin-top:12px">
    <div v-for="(s,i) in streamLabels" :key="i"
      style="padding:6px 12px;border-radius:6px;background:#111827;border:1px solid #1e293b;margin-bottom:4px;font-size:0.82em">
      <span style="color:#38bdf8">{{ s.label }}</span>
      <span style="color:#94a3b8;margin-left:8px">{{ s.status }}</span>
      <span v-if="s.node==='done'" style="color:#4ade80;margin-left:8px">✅</span>
    </div>
  </div>

  <!-- ====== Result ====== -->
  <div v-if="result && !streaming" style="margin-top:16px">
    <div v-if="result.error" style="color:#f87171;padding:16px;background:rgba(248,113,113,0.08);border-radius:8px">
      ❌ {{ result.error }}
    </div>
    <template v-else>
      <div style="font-size:0.8em;color:#64748b;margin-bottom:12px">
        ID: #{{ result.analysis_id }} | 类型: {{ result.task_type }} |
        报告: {{ result.report?.length || 0 }} 字 |
        响应: {{ result.response_plan?.length || 0 }} 字
      </div>
      <!-- Report -->
      <details style="margin-bottom:12px" open>
        <summary style="cursor:pointer;color:#38bdf8;font-weight:600;padding:8px 0">📝 分析报告</summary>
        <pre style="white-space:pre-wrap;font-size:0.85em;color:#e2e8f0;line-height:1.7;font-family:inherit;padding:16px;background:#111827;border-radius:8px;border:1px solid #1e293b;max-height:600px;overflow-y:auto">{{ result.analysis || result.report }}</pre>
      </details>
      <!-- Plan -->
      <details style="margin-bottom:12px">
        <summary style="cursor:pointer;color:#fbbf24;font-weight:600;padding:8px 0">📋 响应计划</summary>
        <pre style="white-space:pre-wrap;font-size:0.85em;color:#e2e8f0;line-height:1.7;font-family:inherit;padding:16px;background:#111827;border-radius:8px;border:1px solid #1e293b;max-height:400px;overflow-y:auto">{{ result.response_plan }}</pre>
      </details>
      <!-- Full Report -->
      <details>
        <summary style="cursor:pointer;color:#4ade80;font-weight:600;padding:8px 0">📄 完整 Markdown 报告</summary>
        <pre style="white-space:pre-wrap;font-size:0.85em;color:#e2e8f0;line-height:1.7;font-family:inherit;padding:16px;background:#111827;border-radius:8px;border:1px solid #1e293b;max-height:500px;overflow-y:auto">{{ result.report }}</pre>
      </details>
    </template>
  </div>

</div>
</template>
