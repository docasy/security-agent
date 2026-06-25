<script setup>
import { ref, nextTick, onMounted, watch } from 'vue'

const API = '/api'

// ===== Threads =====
const threads = ref([])
const activeThread = ref(null) // { id: string, title: string, messages: [...] }
const sidebarOpen = ref(true)

// ===== Message input =====
const input = ref('')
const sending = ref(false)

// ===== Helpers =====
function api(path, opts = {}) {
  return fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  }).then(r => r.ok ? r.json() : r.text().then(t => { throw new Error(t) }))
}

function genThreadId() {
  return 't-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6)
}

// ===== Load threads from SQLite history =====
async function loadThreads() {
  try {
    const raw = await api('/analyses?limit=50')
    // Group by thread_id
    const map = {}
    for (const r of raw) {
      if (!map[r.thread_id]) {
        map[r.thread_id] = {
          id: r.thread_id,
          title: r.input_data?.slice(0, 40) || r.task_type,
          task_type: r.task_type,
          messages: [],
          lastId: r.id,
          createdAt: r.created_at,
        }
      }
      // Add analysis result as assistant message
      if (r.analysis_result) {
        map[r.thread_id].messages.push({
          role: 'assistant',
          content: r.analysis_result,
          type: r.task_type,
          analysisId: r.id,
          responsePlan: r.response_plan,
          report: r.final_report,
          createdAt: r.created_at,
        })
      }
    }
    threads.value = Object.values(map).sort((a, b) => b.lastId - a.lastId)
    // Auto-select latest
    if (threads.value.length > 0 && !activeThread.value) {
      activeThread.value = threads.value[0]
    }
  } catch {}
}

// ===== Send message =====
async function send() {
  const text = input.value.trim()
  if (!text || sending.value) return

  sending.value = true

  // Create thread if needed
  if (!activeThread.value) {
    const tid = genThreadId()
    activeThread.value = { id: tid, title: text.slice(0, 40), messages: [] }
  }

  const thread = activeThread.value
  const isFirst = thread.messages.length === 0

  // Add user message
  const userMsg = { role: 'user', content: text }
  thread.messages.push(userMsg)
  input.value = ''

  // Add streaming placeholder
  const streamMsg = { role: 'assistant', content: '', type: 'streaming', steps: [] }
  thread.messages.push(streamMsg)
  await nextTick()
  scrollToBottom()

  try {
    if (isFirst) {
      // First message: auto-detect intent
      const isPentest = /扫描|渗透|端口|目标|攻击面|侦察|nmap|exploit/i.test(text)
      const mode = isPentest ? 'pentest' : 'analyze'
      thread.task_type = mode

      const body = isPentest
        ? JSON.stringify({ target: extractTarget(text) || text, task_type: 'pentest', thread_id: thread.id })
        : JSON.stringify({ alert_data: text, task_type: 'alert', thread_id: thread.id })

      const resp = await fetch(`${API}/${mode}/stream`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
      })
      await readStream(resp, streamMsg)
    } else {
      // Follow-up: use /chat
      const resp = await api(`/chat/${thread.id}`, {
        method: 'POST',
        body: JSON.stringify({ message: text }),
      })
      streamMsg.content = resp.reply
      streamMsg.type = resp.routed_to_agent || 'chat'
    }
  } catch (e) {
    streamMsg.content = '❌ ' + e.message
    streamMsg.type = 'error'
  }

  sending.value = false
  // Reload threads to pick up new SQLite records
  setTimeout(loadThreads, 1000)
}

function extractTarget(text) {
  // Try to extract IP or domain from message
  const ip = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)
  if (ip) return ip[0]
  const domain = text.match(/\b[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+/)
  if (domain) return domain[0]
  return text
}

async function readStream(resp, streamMsg) {
  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  streamMsg.toolCalls = []   // 正在执行的工具列表
  streamMsg.content = ''     // 累积 token

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

          if (data.type === 'token') {
            // ---- LLM 逐字输出：追加到 content ----
            streamMsg.content += data.content

          } else if (data.type === 'tool_start') {
            // ---- 工具开始执行 ----
            if (!streamMsg.toolCalls) streamMsg.toolCalls = []
            streamMsg.toolCalls.push({ name: data.tool, status: 'running' })

          } else if (data.type === 'tool_end') {
            // ---- 工具执行完毕 ----
            const tc = (streamMsg.toolCalls || []).find(t => t.name === data.tool && t.status === 'running')
            if (tc) tc.status = 'done'

          } else if (data.type === 'done') {
            // ---- 最终完成 ----
            streamMsg.responsePlan = data.response_plan
            streamMsg.report = data.report
            streamMsg.analysisId = data.analysis_id
          }

          await nextTick()
          scrollToBottom()
        } catch {}
      }
    }
  }
}

function scrollToBottom() {
  nextTick(() => {
    const el = document.getElementById('chat-area')
    if (el) el.scrollTop = el.scrollHeight
  })
}

function newThread() {
  activeThread.value = null
  input.value = ''
}

function selectThread(t) {
  activeThread.value = t
}

onMounted(loadThreads)
</script>

<template>
<div style="display:flex;height:100vh;background:#0b1120;color:#e2e8f0">

  <!-- ===== SIDEBAR ===== -->
  <aside v-if="sidebarOpen" style="width:260px;border-right:1px solid #1e293b;display:flex;flex-direction:column;background:#0f172a;flex-shrink:0">
    <div style="padding:16px;border-bottom:1px solid #1e293b">
      <button @click="newThread"
        style="width:100%;padding:10px;border-radius:8px;border:1px solid #38bdf8;background:rgba(56,189,248,0.08);color:#38bdf8;font-weight:600;cursor:pointer;font-size:0.88em">
        + 新对话
      </button>
    </div>
    <div style="flex:1;overflow-y:auto;padding:8px">
      <div v-if="threads.length===0" style="color:#64748b;font-size:0.82em;text-align:center;padding:20px">
        暂无对话历史
      </div>
      <div v-for="t in threads" :key="t.id"
        @click="selectThread(t)"
        :style="{
          padding:'10px 12px',borderRadius:'8px',cursor:'pointer',marginBottom:'4px',
          fontSize:'0.84em',lineHeight:'1.4',
          background: activeThread?.id===t.id ? 'rgba(56,189,248,0.08)' : 'transparent',
          border: activeThread?.id===t.id ? '1px solid rgba(56,189,248,0.3)' : '1px solid transparent',
        }">
        <div style="color:#e2e8f0;overflow:hidden;textOverflow:'ellipsis';whiteSpace:'nowrap'">{{ t.title }}</div>
        <div style="color:#64748b;font-size:0.82em;margin-top:2px">
          {{ t.task_type==='pentest' ? '💣' : '🔍' }} {{ t.messages.length }} 轮
        </div>
      </div>
    </div>
  </aside>

  <!-- ===== TOGGLE SIDEBAR ===== -->
  <button @click="sidebarOpen=!sidebarOpen"
    style="border:none;background:transparent;color:#64748b;cursor:pointer;font-size:1.2em;padding:0 8px;flex-shrink:0"
    :title="sidebarOpen ? '收起侧边栏' : '展开侧边栏'">
    {{ sidebarOpen ? '◀' : '▶' }}
  </button>

  <!-- ===== MAIN CHAT ===== -->
  <div style="flex:1;display:flex;flex-direction:column;min-width:0">

    <!-- Header -->
    <div style="padding:12px 20px;border-bottom:1px solid #1e293b;font-size:0.85em;color:#64748b;display:flex;align-items:center;gap:8px">
      <span style="font-weight:700;color:#e2e8f0">Security Agent</span>
      <span v-if="activeThread?.task_type==='pentest'" style="color:#2dd4bf;font-size:0.82em">| 红队模式</span>
      <span v-if="activeThread?.task_type==='alert'" style="color:#818cf8;font-size:0.82em">| 蓝队模式</span>
    </div>

    <!-- Messages -->
    <div id="chat-area" style="flex:1;overflow-y:auto;padding:16px 20px">

      <!-- Empty state -->
      <div v-if="!activeThread || activeThread.messages.length===0"
        style="text-align:center;padding:80px 20px;color:#64748b">
        <div style="font-size:2em;margin-bottom:16px">🛡️</div>
        <div style="font-size:1.1em;font-weight:600;color:#94a3b8;margin-bottom:8px">Security Agent — 多智能体安全分析</div>
        <div style="font-size:0.88em;line-height:1.8">
          输入 <span style="color:#2dd4bf">IP/域名</span> 进行渗透测试侦察<br>
          输入 <span style="color:#818cf8">告警内容</span> 进行蓝队威胁研判<br>
          Agent 会自动判断你的意图，使用对应的安全工具链
        </div>
      </div>

      <!-- Message bubbles -->
      <div v-for="(msg, i) in activeThread?.messages || []" :key="i" style="margin-bottom:16px">
        <!-- User -->
        <div v-if="msg.role==='user'" style="display:flex;justify-content:flex-end">
          <div style="max-width:75%;padding:10px 16px;border-radius:12px 12px 0 12px;background:#1e293b;font-size:0.9em;line-height:1.6">{{ msg.content }}</div>
        </div>

        <!-- Assistant -->
        <div v-else style="display:flex;flex-direction:column">
          <!-- Tool calls in progress -->
          <div v-if="msg.toolCalls && msg.toolCalls.length>0" style="margin-bottom:6px">
            <span v-for="(tc, j) in msg.toolCalls" :key="j"
              style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.72em;margin-right:6px;margin-bottom:4px"
              :style="{background: tc.status==='done' ? 'rgba(74,222,128,0.1)' : 'rgba(251,191,36,0.1)', border: '1px solid ' + (tc.status==='done' ? 'rgba(74,222,128,0.3)' : 'rgba(251,191,36,0.3)'), color: tc.status==='done' ? '#4ade80' : '#fbbf24'}">
              {{ tc.status==='running' ? '⚡' : '✅' }} {{ tc.name }}
            </span>
          </div>

          <!-- Streaming token text -->
          <div v-if="msg.content || (msg.toolCalls && msg.toolCalls.length>0) && !sending"
            style="max-width:85%;padding:10px 16px;border-radius:12px 12px 12px 0;background:#111827;border:1px solid #1e293b;font-size:0.88em;line-height:1.7">
            <pre style="white-space:pre-wrap;font-family:inherit;margin:0;line-height:1.75">{{ msg.content }}</pre>
            <span v-if="sending" style="display:inline-block;width:8px;height:16px;background:#38bdf8;animation:blink 0.6s infinite;vertical-align:middle;margin-left:2px"></span>
          </div>

          <!-- Static text content (non-streaming) -->
          <div v-if="msg.content && msg.type !== 'streaming'" style="max-width:85%;padding:10px 16px;border-radius:12px 12px 12px 0;background:#111827;border:1px solid #1e293b;font-size:0.88em;line-height:1.7">
            <pre style="white-space:pre-wrap;font-family:inherit;margin:0;line-height:1.75">{{ msg.content }}</pre>
          </div>

          <!-- Response plan collapsible -->
          <details v-if="msg.responsePlan" style="margin-top:8px;margin-left:8px">
            <summary style="cursor:pointer;color:#fbbf24;font-size:0.82em;font-weight:600">📋 响应计划</summary>
            <pre style="white-space:pre-wrap;font-size:0.82em;color:#94a3b8;line-height:1.7;font-family:inherit;padding:12px;background:#111827;border-radius:8px;border:1px solid #1e293b;margin-top:4px;max-height:400px;overflow-y:auto">{{ msg.responsePlan }}</pre>
          </details>

          <!-- Report collapsible -->
          <details v-if="msg.report" style="margin-top:4px;margin-left:8px">
            <summary style="cursor:pointer;color:#4ade80;font-size:0.82em;font-weight:600">📄 完整报告</summary>
            <pre style="white-space:pre-wrap;font-size:0.82em;color:#94a3b8;line-height:1.7;font-family:inherit;padding:12px;background:#111827;border-radius:8px;border:1px solid #1e293b;margin-top:4px;max-height:400px;overflow-y:auto">{{ msg.report }}</pre>
          </details>
        </div>
      </div>

    </div>

    <!-- Input bar -->
    <div style="padding:12px 20px;border-top:1px solid #1e293b">
      <div style="display:flex;gap:8px">
        <input v-model="input" @keyup.enter="send" :disabled="sending"
          :placeholder="sending ? 'Agent 正在分析中...' : (activeThread ? '追问...' : '输入 IP/域名 进行渗透测试，或粘贴告警进行研判...')"
          style="flex:1;padding:10px 16px;border-radius:10px;border:1px solid #334155;background:#111827;color:#e2e8f0;font-size:0.9em;outline:none"
        />
        <button @click="send" :disabled="sending"
          style="padding:10px 20px;border-radius:10px;border:none;background: sending ? '#334155' : '#38bdf8';color:sending ? '#64748b' : '#0b1120';font-weight:600;cursor:sending ? 'not-allowed' : 'pointer';font-size:0.88em">
          {{ sending ? '⏳' : '发送' }}
        </button>
      </div>
      <div style="font-size:0.72em;color:#475569;margin-top:4px;text-align:center">
        所有对话自动持久化 · 左侧可切换历史线程
      </div>
    </div>
  </div>

</div>
</template>
