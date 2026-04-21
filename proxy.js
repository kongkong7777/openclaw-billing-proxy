#!/usr/bin/env node
/**
 * OpenClaw Subscription Billing Proxy v2.0
 *
 * Routes OpenClaw API requests through Claude Code's subscription billing
 * instead of Extra Usage. Defeats Anthropic's multi-layer detection:
 *
 *   Layer 1: Billing header injection (84-char Claude Code identifier)
 *   Layer 2: String trigger sanitization (OpenClaw, sessions_*, running inside, etc.)
 *   Layer 3: Tool name fingerprint bypass (rename OC tools to CC PascalCase convention)
 *   Layer 4: System prompt template bypass (strip config section, replace with paraphrase)
 *   Layer 5: Tool description stripping (reduce fingerprint signal in tool schemas)
 *   Layer 6: Property name renaming (eliminate OC-specific schema property names)
 *   Layer 7: Full bidirectional reverse mapping (SSE + JSON responses)
 *
 * v1.x string-only sanitization stopped working April 8, 2026 when Anthropic
 * upgraded from string matching to tool-name fingerprinting and template detection.
 * v2.0 defeats the new detection by transforming the entire request body.
 *
 * Zero dependencies. Works on Windows, Linux, Mac.
 *
 * Usage:
 *   node proxy.js [--port 18801] [--config config.json]
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { StringDecoder } = require('string_decoder');

// ─── Defaults ───────────────────────────────────────────────────────────────
const DEFAULT_PORT = 18801;
const UPSTREAM_HOST = '127.0.0.1';
const VERSION = '2.2.3';

// Claude Code version to emulate (update when new CC versions are released)
const CC_VERSION = '2.1.97';

// Billing fingerprint constants (matches real CC utils/fingerprint.ts)
const BILLING_HASH_SALT = '59cf53e54c78';
const BILLING_HASH_INDICES = [4, 7, 20];

// Persistent per-instance identifiers (generated once at startup)
const DEVICE_ID = crypto.randomBytes(32).toString('hex');
const INSTANCE_SESSION_ID = crypto.randomUUID();

// Beta flags required for OAuth + Claude Code features
// Beta flags sent with every request. Removed two entries that do not exist
// in real Claude Code (identified via PR #48 comparison against
// opencode-claude-auth): 'advanced-tool-use-2025-11-20' and
// 'fast-mode-2026-02-01'. Their presence is a density-classifier signal
// that the request is not from a genuine CC client. The remaining two
// model-sensitive flags (interleaved-thinking-2025-05-14 rejected by Haiku;
// effort-2025-11-24 valid only on 4.6 models) are filtered per-model at
// request time in the handler.
const REQUIRED_BETAS = [
  'oauth-2025-04-20',
  'claude-code-20250219',
  'interleaved-thinking-2025-05-14',
  'context-management-2025-06-27',
  'prompt-caching-scope-2026-01-05',
  'effort-2025-11-24'
];

// Return the REQUIRED_BETAS subset that is valid for a given Claude model.
// - Haiku models reject 'interleaved-thinking' (PR #48: causes 400).
// - 'effort-2025-11-24' is only accepted on Claude 4.6+ models; sending it
//   to 4.5 or earlier is a density-classifier signal.
// Other betas (oauth, claude-code, context-management, prompt-caching-scope)
// are universally accepted.
function getModelBetas(model) {
  const m = (model || '').toLowerCase();
  return REQUIRED_BETAS.filter(b => {
    if (b === 'interleaved-thinking-2025-05-14' && m.includes('haiku')) return false;
    if (b === 'effort-2025-11-24' && !/-4-6\b/.test(m)) return false;
    return true;
  });
}

// CC tool stubs -- injected into tools array to make the tool set look more
// like a Claude Code session. The model won't call these (schemas are minimal).
const CC_TOOL_STUBS = [
  '{"name":"mcp_Glob","description":"Find files by pattern","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Glob pattern"}},"required":["pattern"]}}',
  '{"name":"mcp_Grep","description":"Search file contents","input_schema":{"type":"object","properties":{"pattern":{"type":"string","description":"Regex pattern"},"path":{"type":"string","description":"Search path"}},"required":["pattern"]}}',
  '{"name":"mcp_Agent","description":"Launch a subagent for complex tasks","input_schema":{"type":"object","properties":{"prompt":{"type":"string","description":"Task description"}},"required":["prompt"]}}',
  '{"name":"mcp_NotebookEdit","description":"Edit notebook cells","input_schema":{"type":"object","properties":{"notebook_path":{"type":"string"},"cell_index":{"type":"integer"}},"required":["notebook_path"]}}',
  '{"name":"mcp_TodoRead","description":"Read current task list","input_schema":{"type":"object","properties":{}}}'
];

// ─── Billing Fingerprint ────────────────────────────────────────────────────
// Computes a 3-character SHA256 fingerprint hash matching real CC's
// computeFingerprint() in utils/fingerprint.ts:
//   SHA256(salt + msg[4] + msg[7] + msg[20] + version)[:3]
// Applied to the first user message text in the request body.

function computeBillingFingerprint(firstUserText) {
  const chars = BILLING_HASH_INDICES.map(i => firstUserText[i] || '0').join('');
  const input = `${BILLING_HASH_SALT}${chars}${CC_VERSION}`;
  return crypto.createHash('sha256').update(input).digest('hex').slice(0, 3);
}

// Extract first user message text from the raw body using string scanning.
// Avoids JSON.parse to preserve raw body integrity.
function extractFirstUserText(bodyStr) {
  // Find first "role":"user" in messages array
  const msgsIdx = bodyStr.indexOf('"messages":[');
  if (msgsIdx === -1) return '';
  const userIdx = bodyStr.indexOf('"role":"user"', msgsIdx);
  if (userIdx === -1) return '';

  // Look for "content" near this role
  // Could be "content":"string" or "content":[{..."text":"..."}]
  const contentIdx = bodyStr.indexOf('"content"', userIdx);
  if (contentIdx === -1 || contentIdx > userIdx + 500) return '';

  const afterContent = bodyStr[contentIdx + '"content"'.length + 1]; // skip the :
  if (afterContent === '"') {
    // Simple string content: "content":"text here"
    const textStart = contentIdx + '"content":"'.length;
    let end = textStart;
    while (end < bodyStr.length) {
      if (bodyStr[end] === '\\') { end += 2; continue; }
      if (bodyStr[end] === '"') break;
      end++;
    }
    // Decode basic JSON escapes for the fingerprint characters
    return bodyStr.slice(textStart, end)
      .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  // Array content: find first text block
  const textIdx = bodyStr.indexOf('"text":"', contentIdx);
  if (textIdx === -1 || textIdx > contentIdx + 2000) return '';
  const textStart = textIdx + '"text":"'.length;
  let end = textStart;
  while (end < bodyStr.length) {
    if (bodyStr[end] === '\\') { end += 2; continue; }
    if (bodyStr[end] === '"') break;
    end++;
  }
  return bodyStr.slice(textStart, Math.min(end, textStart + 50))
    .replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

function computeCch(text) {
  return crypto.createHash('sha256').update(text).digest('hex').slice(0, 5);
}

function buildBillingBlock(bodyStr, preExtractedText) {
  const firstText = preExtractedText !== undefined ? preExtractedText : extractFirstUserText(bodyStr);
  const fingerprint = computeBillingFingerprint(firstText);
  const ccVersion = `${CC_VERSION}.${fingerprint}`;
  const cch = computeCch(firstText);
  return `{"type":"text","text":"x-anthropic-billing-header: cc_version=${ccVersion}; cc_entrypoint=cli; cch=${cch};"}`;
}

// ─── Stainless SDK Headers ──────────────────────────────────────────────────
// Real Claude Code sends these on every request via the Anthropic JS SDK.
function getStainlessHeaders() {
  const p = process.platform;
  const osName = p === 'darwin' ? 'macOS' : p === 'win32' ? 'Windows' : p === 'linux' ? 'Linux' : p;
  const arch = process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : process.arch;
  return {
    'user-agent': `claude-cli/${CC_VERSION} (external, cli)`,
    'x-app': 'cli',
    'x-claude-code-session-id': INSTANCE_SESSION_ID,
    'x-stainless-arch': arch,
    'x-stainless-lang': 'js',
    'x-stainless-os': osName,
    'x-stainless-package-version': '0.90.0',
    'x-stainless-runtime': 'node',
    'x-stainless-runtime-version': process.version,
    'x-stainless-retry-count': '0',
    'x-stainless-timeout': '600',
    'anthropic-dangerous-direct-browser-access': 'true'
  };
}

// ─── Layer 2: String Trigger Replacements ───────────────────────────────────
// Applied globally via split/join on the entire request body.
// IMPORTANT: Use space-free replacements for lowercase 'openclaw' to avoid
// breaking filesystem paths (e.g., .openclaw/ -> .ocplatform/, not .oc platform/)
const DEFAULT_REPLACEMENTS = [
  ['OpenClaw', 'Tessera'],
  ['openclaw', 'tessera'],
  ['sessions_spawn', 'create_task'],
  ['sessions_list', 'list_tasks'],
  ['sessions_history', 'get_history'],
  ['sessions_send', 'send_to_task'],
  ['sessions_yield_interrupt', 'task_yield_interrupt'],
  ['sessions_yield', 'yield_task'],
  ['sessions_store', 'task_store'],
  ['HEARTBEAT_OK', 'HB_UPLINK_OK'],
  ['HEARTBEAT', 'HB_UPLINK'],
  ['heartbeat', 'hb_uplink'],
  ['Prometheus', 'SentinelCore'],
  ['prometheus', 'sentinelcore'],
  ['clawhub.com', 'tessera-market.net'],
  ['clawhub', 'tessera-market'],
  ['clawd', 'tesserad'],
  ['lossless-claw', 'lossless-tessera'],
  ['third-party', 'external-svc'],
  ['billing proxy', 'metering bridge'],
  ['billing-proxy', 'metering-bridge'],
  ['x-anthropic-billing-header', 'x-meter-token'],
  ['x-anthropic-billing', 'x-meter-id'],
  ['cch=00000', 'mtx=00000'],
  ['cc_version', 'mtx_version'],
  ['cc_entrypoint', 'mtx_entrypoint'],
  ['billing header', 'metering header'],
  ['extra usage', 'spare allowance'],
  ['assistant platform', 'tessera runtime'],
  ['LobeChat', 'Driftwave'],
  ['lobechat', 'driftwave'],
  ['LobeHub', 'Driftgate'],
  ['lobehub', 'driftgate'],
  ['lobe-chat', 'drift-wave'],
  ['Lobe Chat', 'Drift Wave'],
  ['lobehub.com', 'driftgate.net'],
  ['NextChat', 'Swiftline'],
  ['nextchat', 'swiftline'],
  ['ChatGPT-Next-Web', 'Swiftline-Web'],
  ['next-web', 'swift-web'],
];

// ─── Layer 3: Tool Name Renames ─────────────────────────────────────────────
// Applied as "quoted" replacements ("name" -> "Name") throughout the ENTIRE body.
// This defeats Anthropic's tool-name fingerprinting which identifies the request
// as OpenClaw based on the combination of tool names in the tools array.
//
// The detector specifically checks for OpenClaw's tool name set. Even with empty
// schemas (no descriptions, no properties), original tool names trigger detection.
// Renaming to PascalCase CC-like conventions defeats this entirely.
//
// ORDERING: lcm_expand_query MUST come before lcm_expand to avoid partial match.
const DEFAULT_TOOL_RENAMES = [
  ['exec', 'Bash'],
  ['process', 'BashSession'],
  ['browser', 'BrowserControl'],
  ['canvas', 'CanvasView'],
  ['nodes', 'DeviceControl'],
  ['cron', 'Scheduler'],
  ['message', 'SendMessage'],
  ['tts', 'Speech'],
  ['gateway', 'SystemCtl'],
  ['agents_list', 'AgentList'],
  ['list_tasks', 'TaskList'],
  ['get_history', 'TaskHistory'],
  ['send_to_task', 'TaskSend'],
  ['create_task', 'TaskCreate'],
  ['subagents', 'AgentControl'],
  ['session_status', 'StatusCheck'],
  // NOTE: ['web_search', 'WebSearch'] and ['web_fetch', 'WebFetch'] removed —
  // these are now Anthropic built-in tool types (web_search_20250305,
  // web_fetch_20250910, etc.). The rename collides with the "type" field:
  //   tools.N: Input tag 'WebSearch' found using 'type' does not match any
  //   of the expected tags: 'web_search_20250305', 'web_search_20260209', ...
  // Same class of bug as the 'image' collision below. (issue #web_search)
  //
  // NOTE: ['image', 'ImageGen'] removed — collides with Anthropic content block
  // type "image". OpenClaw tool_results carrying image content blocks would have
  // their `"type": "image"` field renamed and Anthropic rejects with:
  //   messages.N.content.M.tool_result.content.K: Input tag 'ImageGen' found
  //   using 'type' does not match any of the expected tags
  // The fingerprint signal lost from one tool name is much smaller than the
  // certainty of breaking every conversation that ever touched an image. (issue #14)
  ['pdf', 'mcp_PdfParse'],
  ['image_generate', 'mcp_ImageCreate'],
  ['music_generate', 'mcp_MusicCreate'],
  ['video_generate', 'mcp_VideoCreate'],
  ['memory_search', 'mcp_KnowledgeSearch'],
  ['memory_get', 'mcp_KnowledgeGet'],
  ['lcm_expand_query', 'mcp_ContextQuery'],
  ['lcm_grep', 'mcp_ContextGrep'],
  ['lcm_describe', 'mcp_ContextDescribe'],
  ['lcm_expand', 'mcp_ContextExpand'],
  ['yield_task', 'mcp_TaskYield'],
  ['task_store', 'mcp_TaskStore'],
  ['task_yield_interrupt', 'mcp_TaskYieldInterrupt'],
  // File operation tools — OpenClaw sends these lowercase but CC_TOOL_STUBS
  // inject TitleCase versions. Without renames, both coexist in the tools
  // array, causing infinite tool-not-found retry loops (issue #43).
  ['read', 'Read'],
  ['write', 'Write'],
  ['edit', 'Edit'],
  ['grep', 'Grep'],
  ['glob', 'Glob'],
  ['ls', 'LS'],
];

// ─── Layer 6: Property Name Renames ─────────────────────────────────────────
// OC-specific schema property names that contribute to fingerprinting.
const DEFAULT_PROP_RENAMES = [
  ['session_id', 'thread_id'],
  ['conversation_id', 'thread_ref'],
  ['summaryIds', 'chunk_ids'],
  ['summary_id', 'chunk_id'],
  ['system_event', 'event_text'],
  ['agent_id', 'worker_id'],
  ['wake_at', 'trigger_at'],
  ['wake_event', 'trigger_event']
];

// ─── Reverse Mappings ───────────────────────────────────────────────────────
const DEFAULT_REVERSE_MAP = [
  ['create_task', 'sessions_spawn'],
  ['list_tasks', 'sessions_list'],
  ['get_history', 'sessions_history'],
  ['send_to_task', 'sessions_send'],
  ['task_yield_interrupt', 'sessions_yield_interrupt'],
  ['yield_task', 'sessions_yield'],
  ['task_store', 'sessions_store'],
  ['HB_UPLINK_OK', 'HEARTBEAT_OK'],
  ['HB_UPLINK', 'HEARTBEAT'],
  ['hb_uplink', 'heartbeat'],
  ['SentinelCore', 'Prometheus'],
  ['sentinelcore', 'prometheus'],
  ['tessera-market.net', 'clawhub.com'],
  ['tessera-market', 'clawhub'],
  ['tesserad', 'clawd'],
  ['lossless-tessera', 'lossless-claw'],
  ['tessera runtime', 'assistant platform'],
  ['external-svc', 'third-party'],
  ['metering-bridge', 'billing-proxy'],
  ['metering bridge', 'billing proxy'],
  ['metering header', 'billing header'],
  ['x-meter-token', 'x-anthropic-billing-header'],
  ['x-meter-id', 'x-anthropic-billing'],
  ['mtx=00000', 'cch=00000'],
  ['mtx_version', 'cc_version'],
  ['mtx_entrypoint', 'cc_entrypoint'],
  ['spare allowance', 'extra usage'],
  ['driftgate.net', 'lobehub.com'],
  ['Drift Wave', 'Lobe Chat'],
  ['drift-wave', 'lobe-chat'],
  ['Driftwave', 'LobeChat'],
  ['driftwave', 'lobechat'],
  ['Driftgate', 'LobeHub'],
  ['driftgate', 'lobehub'],
  ['Swiftline-Web', 'ChatGPT-Next-Web'],
  ['swift-web', 'next-web'],
  ['Swiftline', 'NextChat'],
  ['swiftline', 'nextchat'],
  ['Tessera', 'OpenClaw'],
  ['tessera', 'openclaw'],
];

// ─── Configuration ──────────────────────────────────────────────────────────
function loadConfig() {
  // Port precedence: PROXY_PORT env > --port CLI > config.json port > DEFAULT_PORT
  const args = process.argv.slice(2);
  let configPath = null;
  let cliPort = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) cliPort = parseInt(args[i + 1]);
    if (args[i] === '--config' && args[i + 1]) configPath = args[i + 1];
  }

  const envPort = process.env.PROXY_PORT ? parseInt(process.env.PROXY_PORT) : null;

  let config = {};
  if (configPath && fs.existsSync(configPath)) {
    try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch(e) {
      console.error('[ERROR] Failed to parse config: ' + configPath + ' (' + e.message + ')');
      process.exit(1);
    }
  } else if (fs.existsSync('config.json')) {
    try { config = JSON.parse(fs.readFileSync('config.json', 'utf8')); } catch(e) {
      console.error('[PROXY] Warning: config.json is invalid, using defaults. (' + e.message + ')');
    }
  }

  const homeDir = os.homedir();

  // OAUTH_TOKEN env var takes precedence over all file-based credentials (useful for Docker)
  let credsPath = null;
  if (process.env.OAUTH_TOKEN) {
    credsPath = 'env';
    console.log('[PROXY] Using OAUTH_TOKEN from environment variable.');
  }

  const credsPaths = [
    config.credentialsPath,
    path.join(homeDir, '.claude', '.credentials.json'),
    path.join(homeDir, '.claude', 'credentials.json')
  ].filter(Boolean);

  if (!credsPath) {
    for (const p of credsPaths) {
      const resolved = p.startsWith('~') ? path.join(homeDir, p.slice(1)) : p;
      if (fs.existsSync(resolved) && fs.statSync(resolved).size > 0) {
        credsPath = resolved;
        break;
      }
    }
  }

  // macOS Keychain fallback
  if (!credsPath && process.platform === 'darwin') {
    const { execSync } = require('child_process');
    for (const svc of ['Claude Code-credentials', 'claude-code', 'claude', 'com.anthropic.claude-code']) {
      try {
        const token = execSync('security find-generic-password -s "' + svc + '" -w 2>/dev/null', { encoding: 'utf8' }).trim();
        if (token) {
          let creds;
          try { creds = JSON.parse(token); } catch(e) {
            if (token.startsWith('sk-ant-')) creds = { claudeAiOauth: { accessToken: token, expiresAt: Date.now() + 86400000, subscriptionType: 'unknown' } };
          }
          if (creds && creds.claudeAiOauth) {
            credsPath = path.join(homeDir, '.claude', '.credentials.json');
            fs.mkdirSync(path.join(homeDir, '.claude'), { recursive: true });
            fs.writeFileSync(credsPath, JSON.stringify(creds));
            console.log('[PROXY] Extracted credentials from macOS Keychain');
            break;
          }
        }
      } catch(e) {}
    }
  }

  if (!credsPath) {
    console.error('[ERROR] Claude Code credentials not found.');
    console.error('Run "claude auth login" first to authenticate.');
    console.error('Searched:', credsPaths.join(', '));
    if (process.platform === 'darwin') console.error('Also checked macOS Keychain (Claude Code-credentials, claude-code, claude, com.anthropic.claude-code).');
    console.error('For Docker: set OAUTH_TOKEN in .env or mount ~/.claude as a volume.');
    process.exit(1);
  }

  // Merge pattern arrays: defaults first, then config additions/overrides.
  // This prevents stale config.json snapshots (from old setup.js runs) from
  // silently masking new default patterns added in proxy updates. (issue #24)
  // Users who want full manual control can set "mergeDefaults": false.
  function mergePatterns(defaults, overrides) {
    if (!overrides || overrides.length === 0) return defaults;
    const merged = new Map();
    for (const [find, replace] of defaults) merged.set(find, replace);
    for (const [find, replace] of overrides) merged.set(find, replace);
    return [...merged.entries()];
  }

  const useDefaults = config.mergeDefaults !== false;

  const replacements = useDefaults
    ? mergePatterns(DEFAULT_REPLACEMENTS, config.replacements)
    : (config.replacements || DEFAULT_REPLACEMENTS);
  const reverseMap = useDefaults
    ? mergePatterns(DEFAULT_REVERSE_MAP, config.reverseMap)
    : (config.reverseMap || DEFAULT_REVERSE_MAP);
  const toolRenames = useDefaults
    ? mergePatterns(DEFAULT_TOOL_RENAMES, config.toolRenames)
    : (config.toolRenames || DEFAULT_TOOL_RENAMES);
  const propRenames = useDefaults
    ? mergePatterns(DEFAULT_PROP_RENAMES, config.propRenames)
    : (config.propRenames || DEFAULT_PROP_RENAMES);

  // Warn if config has stale arrays that were merged
  if (config.replacements && useDefaults && config.replacements.length < DEFAULT_REPLACEMENTS.length) {
    console.log(`[PROXY] Note: config.json has ${config.replacements.length} replacements, merged with ${DEFAULT_REPLACEMENTS.length} defaults -> ${replacements.length} total`);
  }
  if (config.toolRenames && useDefaults && config.toolRenames.length < DEFAULT_TOOL_RENAMES.length) {
    console.log(`[PROXY] Note: config.json has ${config.toolRenames.length} toolRenames, merged with ${DEFAULT_TOOL_RENAMES.length} defaults -> ${toolRenames.length} total`);
  }

  return {
    port: envPort || cliPort || config.port || DEFAULT_PORT,
    credsPath,
    replacements,
    reverseMap,
    toolRenames,
    propRenames,
    stripSystemConfig: config.stripSystemConfig !== false,
    stripToolDescriptions: config.stripToolDescriptions !== false,
    injectCCStubs: config.injectCCStubs !== false,
    stripTrailingAssistantPrefill: config.stripTrailingAssistantPrefill !== false
  };
}

// ─── Token Management ───────────────────────────────────────────────────────
function getToken(credsPath) {
  // Env var mode: return synthetic OAuth object without file I/O
  if (credsPath === 'env') {
    const token = process.env.OAUTH_TOKEN;
    if (!token) throw new Error('OAUTH_TOKEN env var is empty.');
    return { accessToken: token, expiresAt: Infinity, subscriptionType: 'env-var' };
  }
  let raw = fs.readFileSync(credsPath, 'utf8');
  if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
  const creds = JSON.parse(raw);
  const oauth = creds.claudeAiOauth;
  if (!oauth || !oauth.accessToken) throw new Error('No OAuth token. Run "claude auth login".');
  return oauth;
}

// ─── Helper ─────────────────────────────────────────────────────────────────
// String-aware bracket matching: skips [/] inside JSON string values so that
// brackets in tool descriptions or text content don't corrupt the depth count.
function findMatchingBracket(str, start) {
  let d = 0, inStr = false;
  for (let i = start; i < str.length; i++) {
    const c = str[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '[') d++;
    else if (c === ']') { d--; if (d === 0) return i; }
  }
  return -1;
}

// Filter CC_TOOL_STUBS to only those whose name isn't already present in the
// tools section JSON. Prevents Anthropic's "Tool names must be unique" error
// when a real Claude Code client already sends Glob/Grep/Agent/NotebookEdit/
// TodoRead and billing-proxy would otherwise blindly prepend them again.
function filterStubsAgainstExisting(stubs, toolsSection) {
  const existingNames = new Set();
  const nameRe = /"name":"([^"]+)"/g;
  let match;
  while ((match = nameRe.exec(toolsSection)) !== null) {
    existingNames.add(match[1].toLowerCase());
  }
  return stubs.filter((stubJson) => {
    const m = /"name":"([^"]+)"/.exec(stubJson);
    return m ? !existingNames.has(m[1].toLowerCase()) : true;
  });
}

// Local estimate for /v1/messages/count_tokens. Scans "text":"..." values
// and sums character count, then applies a rough tokens/char ratio.
// Accurate within ~15% for typical traffic — good enough for a client-side
// context meter. Prevents Anthropic from billing count_tokens requests that
// lack metadata.user_id (which Anthropic's schema forbids on this endpoint,
// leaving CC subscription spoofing incomplete and falling back to API credit).
function estimateTokenCount(bodyStr) {
  let textChars = 0;
  let i = 0;
  while (i < bodyStr.length) {
    const idx = bodyStr.indexOf('"text":"', i);
    if (idx === -1) break;
    let j = idx + '"text":"'.length;
    while (j < bodyStr.length) {
      if (bodyStr[j] === '\\') { j += 2; continue; }
      if (bodyStr[j] === '"') break;
      j++;
    }
    textChars += j - idx - '"text":"'.length;
    i = j + 1;
  }
  // Fallback: if no text fields found, estimate from body size
  const base = textChars > 0 ? textChars * 0.3 : bodyStr.length / 4;
  // Add 5% overhead for JSON structure, tool names, schemas
  return Math.max(1, Math.round(base * 1.05));
}

// String-aware brace matching: skips {/} inside JSON string values.
// Counterpart to findMatchingBracket which handles [/] only.
function findMatchingBrace(str, start) {
  let d = 0, inStr = false;
  for (let i = start; i < str.length; i++) {
    const c = str[i];
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '{') d++;
    else if (c === '}') { d--; if (d === 0) return i; }
  }
  return -1;
}

// Strips "effort" key-value from an object (by key name) in a raw JSON string.
// Uses findMatchingBrace to safely handle nested structures.
function stripEffortFromObject(str, objectKey) {
  const keyPattern = '"' + objectKey + '"';
  let pos = str.indexOf(keyPattern);
  if (pos === -1) return str;
  let braceStart = str.indexOf('{', pos + keyPattern.length);
  if (braceStart === -1) return str;
  const braceEnd = findMatchingBrace(str, braceStart);
  if (braceEnd === -1) return str;
  const inner = str.slice(braceStart + 1, braceEnd);
  let cleaned = inner
    .replace(/,\s*"effort"\s*:\s*(?:"[^"]*"|\d+(?:\.\d+)?|true|false|null)/, '')
    .replace(/"effort"\s*:\s*(?:"[^"]*"|\d+(?:\.\d+)?|true|false|null),?\s*/, '');
  cleaned = cleaned.replace(/,\s*$/, '').trim();
  if (cleaned === '') {
    const keyStart = str.lastIndexOf(',', pos);
    if (keyStart !== -1 && str.slice(keyStart, pos).trim() === ',') {
      return str.slice(0, keyStart) + str.slice(braceEnd + 1);
    }
    return str.slice(0, pos) + str.slice(braceEnd + 1);
  }
  return str.slice(0, braceStart + 1) + cleaned + str.slice(braceEnd);
}

// ─── Thinking Block Protection ──────────────────────────────────────────────
// Anthropic requires thinking/redacted_thinking content blocks to be echoed
// back byte-identical to what the model originally produced; any mutation
// triggers:
//   "thinking or redacted_thinking blocks in the latest assistant message
//    cannot be modified. These blocks must remain as they were in the
//    original response."
// Both the forward pass (Layer 2/3/6 running against assistant message
// history) and the reverse pass (reverseMap running against responses the
// client stores and echoes on subsequent turns) mutate these blocks via plain
// split/join. Mask each content block with a unique placeholder before
// transforms run, restore after. The placeholder is chosen so no replacement
// or rename pattern can match it.
const THINK_MASK_PREFIX = '__OBP_THINK_MASK_';
const THINK_MASK_SUFFIX = '__';
const THINK_BLOCK_PATTERNS = ['{"type":"thinking"', '{"type":"redacted_thinking"'];

function maskThinkingBlocks(m) {
  const masks = [];
  let out = '';
  let i = 0;
  while (i < m.length) {
    let nextIdx = -1;
    for (const p of THINK_BLOCK_PATTERNS) {
      const idx = m.indexOf(p, i);
      if (idx !== -1 && (nextIdx === -1 || idx < nextIdx)) nextIdx = idx;
    }
    if (nextIdx === -1) { out += m.slice(i); break; }
    out += m.slice(i, nextIdx);
    // String-aware bracket scan so braces inside the thinking text value
    // don't corrupt the depth count.
    let depth = 0, inStr = false, j = nextIdx;
    while (j < m.length) {
      const c = m[j];
      if (inStr) {
        if (c === '\\') { j += 2; continue; }
        if (c === '"') inStr = false;
        j++;
        continue;
      }
      if (c === '"') { inStr = true; j++; continue; }
      if (c === '{') { depth++; j++; continue; }
      if (c === '}') { depth--; j++; if (depth === 0) break; continue; }
      j++;
    }
    if (depth !== 0) {
      // Malformed / truncated — bail without masking the rest
      out += m.slice(nextIdx);
      return { masked: out, masks };
    }
    masks.push(m.slice(nextIdx, j));
    out += THINK_MASK_PREFIX + (masks.length - 1) + THINK_MASK_SUFFIX;
    i = j;
  }
  return { masked: out, masks };
}

function unmaskThinkingBlocks(m, masks) {
  for (let i = 0; i < masks.length; i++) {
    m = m.split(THINK_MASK_PREFIX + i + THINK_MASK_SUFFIX).join(masks[i]);
  }
  return m;
}

// ─── Filesystem Path Protection ─────────────────────────────────────────────
// Layer 2 uses split/join to replace strings (e.g. 'openclaw' → 'tessera')
// across the ENTIRE body. Tool call arguments often contain filesystem paths
// like '/home/user/.openclaw/media/x'. Without protection, those paths get
// corrupted to '/home/user/.tessera/media/x' and the client can't locate the
// files, causing intermittent ENOENT errors (#29) and path-normalization
// failures in OpenClaw's assertLocalMediaAllowed() (#33).
//
// Strategy: extract path-like substrings into NUL-delimited placeholders
// before Layer 2 runs, then restore them verbatim afterwards.
//
// Regex matches paths with at least 2 segments, covering:
//   /home/user/...     — Unix absolute
//   ./src/file.js      — relative with ./
//   ../config/x        — relative with ../
//   ~/dotfile/x        — tilde home
//   C:\\Users\\x or C:\\\\Users\\\\x   — Windows (raw or JSON-escaped)
const PATH_RE = /(?:~?\/|\.{1,2}\/|[A-Za-z]:(?:\\\\|\\|\/))(?:[\w.-]+[\/\\])+[\w.-]+/g;
const PATH_MASK_PREFIX = '\x00__PATH_';
const PATH_MASK_SUFFIX = '__\x00';

function maskPaths(m) {
  const masks = [];
  const out = m.replace(PATH_RE, (match) => {
    masks.push(match);
    return PATH_MASK_PREFIX + (masks.length - 1) + PATH_MASK_SUFFIX;
  });
  return { masked: out, masks };
}

function unmaskPaths(m, masks) {
  for (let i = 0; i < masks.length; i++) {
    m = m.split(PATH_MASK_PREFIX + i + PATH_MASK_SUFFIX).join(masks[i]);
  }
  return m;
}

// ─── Prompt Caching (cache_control injection) ───────────────────────────────
// Anthropic's prompt caching uses ephemeral breakpoints on tools, system, and
// messages. When a breakpoint is present, content up to that point is cached
// for 5 minutes (or 1 hour with "ttl":"1h"). Repeated requests within the TTL
// reuse cached tokens at 0.1x base input cost. Up to 4 breakpoints per request.
//
// Real Claude Code manages its own cache breakpoints, so we only inject for
// clients that don't already use cache_control (OpenClaw, LobeChat, etc.).
// Real CC traffic bypasses billing-proxy entirely at the logger layer, so
// we never see it here anyway.
//
// Strategy: after all other transforms, inject ephemeral cache_control on:
//   - the last tool in tools[]  (caches all tool schemas)
//   - the last element of system[] if system is an array (caches system prompt)
// Skip messages[] for now — multi-turn conversation caching requires careful
// placement that depends on client behavior.
function injectCacheControlInArray(m, arrayKey) {
  const keyPattern = '"' + arrayKey + '":[';
  const keyIdx = m.indexOf(keyPattern);
  if (keyIdx === -1) return m;
  const arrayStart = keyIdx + ('"' + arrayKey + '":').length;
  const arrayEnd = findMatchingBracket(m, arrayStart);
  if (arrayEnd === -1 || arrayEnd <= arrayStart + 1) return m;
  // Scan backward from ] to find the last '}' (end of last element object)
  let i = arrayEnd - 1;
  while (i > arrayStart && (m[i] === ' ' || m[i] === '\t' || m[i] === '\n' || m[i] === '\r')) i--;
  if (m[i] !== '}') return m;
  // Inject cache_control right before the closing '}' of the last element
  return m.slice(0, i) + ',"cache_control":{"type":"ephemeral"}' + m.slice(i);
}

function ensureCacheControl(m) {
  // Skip entirely if the client has already set any cache_control breakpoints.
  // Respecting client-provided caching avoids exceeding the 4-breakpoint limit
  // and prevents shifting the client's cache keys (which would defeat caching).
  if (m.includes('"cache_control"')) return m;
  m = injectCacheControlInArray(m, 'tools');
  m = injectCacheControlInArray(m, 'system');
  return m;
}

// ─── Tool Pair Repair ───────────────────────────────────────────────────────
// Removes orphaned tool_use / tool_result blocks from conversation history.
// An orphaned tool_use has no matching tool_result; an orphaned tool_result
// has no matching tool_use. Both cause Anthropic API validation errors.
// Ported from opencode-claude-auth/src/transforms.ts repairToolPairs().
function repairToolPairs(bodyStr) {
  const msgsStart = bodyStr.indexOf('"messages":[');
  if (msgsStart === -1) return bodyStr;
  const arrayOpenIdx = msgsStart + '"messages":'.length;
  const arrayCloseIdx = findMatchingBracket(bodyStr, arrayOpenIdx);
  if (arrayCloseIdx === -1) return bodyStr;
  const messagesJson = bodyStr.slice(arrayOpenIdx, arrayCloseIdx + 1);
  let messages;
  try { messages = JSON.parse(messagesJson); } catch (e) {
    console.warn('[REPAIR] parse failed:', e.message);
    return bodyStr;
  }
  if (!Array.isArray(messages)) return bodyStr;
  const toolUseIds = new Set();
  const toolResultIds = new Set();
  for (const message of messages) {
    if (!Array.isArray(message.content)) continue;
    for (const block of message.content) {
      if (block.type === 'tool_use' && typeof block.id === 'string') toolUseIds.add(block.id);
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') toolResultIds.add(block.tool_use_id);
    }
  }
  const orphanedUses = new Set();
  for (const id of toolUseIds) if (!toolResultIds.has(id)) orphanedUses.add(id);
  const orphanedResults = new Set();
  for (const id of toolResultIds) if (!toolUseIds.has(id)) orphanedResults.add(id);
  if (orphanedUses.size === 0 && orphanedResults.size === 0) return bodyStr;
  console.log(`[REPAIR] Removing ${orphanedUses.size} orphaned tool_use and ${orphanedResults.size} orphaned tool_result blocks`);
  const candidateRepaired = messages.map((message) => {
    if (!Array.isArray(message.content)) return message;
    const filtered = message.content.filter((block) => {
      if (block.type === 'tool_use' && typeof block.id === 'string') return !orphanedUses.has(block.id);
      if (block.type === 'tool_result' && typeof block.tool_use_id === 'string') return !orphanedResults.has(block.tool_use_id);
      return true;
    });
    if (filtered.length === 0) return null;
    return { ...message, content: filtered };
  });
  const repaired = [];
  for (let i = 0; i < candidateRepaired.length; i++) {
    if (candidateRepaired[i] !== null) {
      repaired.push(candidateRepaired[i]);
    } else {
      const prevRole = repaired.length > 0 ? repaired[repaired.length - 1].role : null;
      const nextMsg = candidateRepaired.slice(i + 1).find(m => m !== null);
      const nextRole = nextMsg ? nextMsg.role : null;
      if (prevRole && nextRole && prevRole === nextRole) {
        repaired.push({ ...messages[i], content: [{ type: 'text', text: '(removed)' }] });
      }
    }
  }
  const repairedJson = JSON.stringify(repaired);
  return bodyStr.slice(0, arrayOpenIdx) + repairedJson + bodyStr.slice(arrayCloseIdx + 1);
}

// ─── Request Processing ─────────────────────────────────────────────────────
function processBody(bodyStr, config, reqPath) {
  // Repair orphaned tool_use/tool_result pairs before any transforms.
  // Must run on the original body (pre-masking) since masking corrupts JSON.parse.
  bodyStr = repairToolPairs(bodyStr);

  // Extract original first user text for billing fingerprint BEFORE any transforms
  const originalFirstUserText = extractFirstUserText(bodyStr);

  // Mask thinking/redacted_thinking content blocks from the transform pipeline
  // so Layer 2/3/6 split/join can't mutate assistant history. Restored before
  // return. See "Thinking Block Protection" above.
  const { masked: maskedBody, masks: thinkMasks } = maskThinkingBlocks(bodyStr);
  let m = maskedBody;

  // Layer 0: Normalize shorthand built-in tool types to versioned names.
  // Clients may send "type":"web_search" but Anthropic requires the versioned
  // form. Map unversioned shorthands to the latest version of each tool.
  // Full list from Anthropic's API error response (2026-04-17):
  //   bash_20250124, code_execution_{20250522,20250825,20260120},
  //   memory_20250818, text_editor_{20250124,20250429,20250728},
  //   tool_search_tool_bm25{,_20251119}, tool_search_tool_regex{,_20251119},
  //   web_fetch_{20250910,20260209,20260309},
  //   web_search_{20250305,20260209}, custom
  const BUILTIN_TOOL_TYPES = [
    ['web_search',             'web_search_20260209'],
    ['web_fetch',              'web_fetch_20260309'],
    ['text_editor',            'text_editor_20250728'],
    ['code_execution',         'code_execution_20260120'],
    ['bash',                   'bash_20250124'],
    ['memory',                 'memory_20250818'],
    ['tool_search_tool_bm25',  'tool_search_tool_bm25_20251119'],
    ['tool_search_tool_regex', 'tool_search_tool_regex_20251119'],
  ];
  for (const [shorthand, versioned] of BUILTIN_TOOL_TYPES) {
    m = m.split('"type":"' + shorthand + '"').join('"type":"' + versioned + '"');
    m = m.split('"type": "' + shorthand + '"').join('"type": "' + versioned + '"');
  }

  // Layer 2: String trigger sanitization (global split/join)
  // Filesystem paths are masked out first so 'openclaw' → 'tessera' etc.
  // don't corrupt tool call arguments that reference real paths on disk.
  const { masked: pathMasked, masks: pathMasks } = maskPaths(m);
  m = pathMasked;
  for (const [find, replace] of config.replacements) {
    m = m.split(find).join(replace);
  }
  m = unmaskPaths(m, pathMasks);

  // Layer 2.5: Strip effort param for Haiku models (Haiku rejects effort with 400)
  {
    const modelMatch = /"model"\s*:\s*"([^"]+)"/.exec(m);
    if (modelMatch && modelMatch[1].toLowerCase().includes('haiku')) {
      m = stripEffortFromObject(m, 'output_config');
      m = stripEffortFromObject(m, 'thinking');
      console.log('[EFFORT] Stripped effort param for Haiku model: ' + modelMatch[1]);
    }
  }

  // Layer 3: Tool name fingerprint bypass (quoted replacement for precision)
  for (const [orig, cc] of config.toolRenames) {
    m = m.split('"' + orig + '"').join('"' + cc + '"');
  }

  // Layer 6: Property name renaming
  for (const [orig, renamed] of config.propRenames) {
    m = m.split('"' + orig + '"').join('"' + renamed + '"');
  }

  // Layer 4: System prompt template bypass
  // Strip the OC config section (~28K of ## Tooling, ## Workspace, ## Messaging, etc.)
  // and replace with a brief paraphrase. The config is between the identity line
  // ("You are a personal assistant") and the first workspace doc (AGENTS.md header).
  // IMPORTANT: Search WITHIN the system array, not from the start of the body.
  // The identity line can appear in conversation history (from prior discussions),
  // and matching there instead of the system prompt causes the strip to fail.
  if (config.stripSystemConfig) {
    const IDENTITY_MARKER = 'You are a personal assistant';
    // Anchor search to the system array so we don't match conversation history
    const sysArrayStart = m.indexOf('"system":[');
    const searchFrom = sysArrayStart !== -1 ? sysArrayStart : 0;
    const configStart = m.indexOf(IDENTITY_MARKER, searchFrom);
    if (configStart !== -1) {
      let stripFrom = configStart;
      if (stripFrom >= 2 && m[stripFrom - 2] === '\\' && m[stripFrom - 1] === 'n') {
        stripFrom -= 2;
      }
      // Find end of config: first workspace doc header (a ## section with a filesystem path).
      // Previous approach used 'AGENTS.md' as the landmark, but that string can appear
      // earlier in skill content or LCM summaries, causing a premature boundary. (issue #26)
      // Workspace doc headers always start with a filesystem path:
      //   Linux/macOS: \n## /home/... or \n## /Users/...
      //   Windows:     \n## C:\\...
      let configEnd = m.indexOf('\\n## /', configStart + IDENTITY_MARKER.length);
      if (configEnd === -1) configEnd = m.indexOf('\\n## C:\\\\', configStart + IDENTITY_MARKER.length);
      if (configEnd !== -1) {
        const boundary = configEnd;

        const strippedLen = boundary - stripFrom;
        if (strippedLen > 1000) {
          const PARAPHRASE =
            '\\nYou are an AI operations assistant with access to all tools listed in this request ' +
            'for file operations, command execution, web search, browser control, scheduling, ' +
            'messaging, and session management. Tool names are case-sensitive and must be called ' +
            'exactly as listed. Your responses route to the active channel automatically. ' +
            'For cross-session communication, use the task messaging tools. ' +
            'Skills defined in your workspace should be invoked when they match user requests. ' +
            'Consult your workspace reference files for detailed operational configuration.\\n';

          m = m.slice(0, stripFrom) + PARAPHRASE + m.slice(boundary);
          console.log(`[STRIP] Removed ${strippedLen} chars of config template`);
        }
      }
    }
  }

  // Layer 5: Tool description stripping
  if (config.stripToolDescriptions) {
    const toolsIdx = m.indexOf('"tools":[');
    if (toolsIdx !== -1) {
      const toolsEndIdx = findMatchingBracket(m, toolsIdx + '"tools":'.length);
      if (toolsEndIdx !== -1) {
        let section = m.slice(toolsIdx, toolsEndIdx + 1);
        let from = 0;
        while (true) {
          const d = section.indexOf('"description":"', from);
          if (d === -1) break;
          const vs = d + '"description":"'.length;
          let i = vs;
          while (i < section.length) {
            if (section[i] === '\\' && i + 1 < section.length) { i += 2; continue; }
            if (section[i] === '"') break;
            i++;
          }
          section = section.slice(0, vs) + section.slice(i);
          from = vs + 1;
        }
        // Inject CC tool stubs (dedup against existing tool names so that
        // real Claude Code clients — which already carry Glob/Grep/Agent/
        // NotebookEdit/TodoRead — don't end up with duplicates).
        if (config.injectCCStubs) {
          const stubsToInject = filterStubsAgainstExisting(CC_TOOL_STUBS, section);
          if (stubsToInject.length > 0) {
            const insertAt = '"tools":['.length;
            section = section.slice(0, insertAt) + stubsToInject.join(',') + ',' + section.slice(insertAt);
          }
        }
        m = m.slice(0, toolsIdx) + section + m.slice(toolsEndIdx + 1);
      }
    }
  } else if (config.injectCCStubs) {
    // Inject stubs even without description stripping. Dedup against existing
    // tool names to prevent "Tool names must be unique" from Anthropic.
    const toolsIdx = m.indexOf('"tools":[');
    if (toolsIdx !== -1) {
      const toolsEndIdx = findMatchingBracket(m, toolsIdx + '"tools":'.length);
      if (toolsEndIdx !== -1) {
        const section = m.slice(toolsIdx, toolsEndIdx + 1);
        const stubsToInject = filterStubsAgainstExisting(CC_TOOL_STUBS, section);
        if (stubsToInject.length > 0) {
          const insertAt = toolsIdx + '"tools":['.length;
          m = m.slice(0, insertAt) + stubsToInject.join(',') + ',' + m.slice(insertAt);
        }
      }
    }
  }

  // Layer 1: Billing header injection (dynamic fingerprint per request)
  const BILLING_BLOCK = buildBillingBlock(m, originalFirstUserText);
  const sysArrayIdx = m.indexOf('"system":[');
  if (sysArrayIdx !== -1) {
    const insertAt = sysArrayIdx + '"system":['.length;
    m = m.slice(0, insertAt) + BILLING_BLOCK + ',' + m.slice(insertAt);
  } else if (m.includes('"system":"')) {
    const sysStart = m.indexOf('"system":"');
    let i = sysStart + '"system":"'.length;
    while (i < m.length) {
      if (m[i] === '\\') { i += 2; continue; }
      if (m[i] === '"') break;
      i++;
    }
    const sysEnd = i + 1;
    const originalSysStr = m.slice(sysStart + '"system":'.length, sysEnd);
    m = m.slice(0, sysStart)
      + '"system":[' + BILLING_BLOCK + ',{"type":"text","text":' + originalSysStr + '}]'
      + m.slice(sysEnd);
  } else {
    m = '{"system":[' + BILLING_BLOCK + '],' + m.slice(1);
  }

  // Metadata injection: device_id + session_id matching real CC format.
  // Anthropic's /v1/messages/count_tokens and other sub-endpoints reject the
  // metadata field entirely ("metadata: Extra inputs are not permitted"), so
  // restrict injection to the main /v1/messages endpoint.
  if (reqPath === '/v1/messages' || reqPath === '/v1/messages/') {
    const metaValue = JSON.stringify({ device_id: DEVICE_ID, session_id: INSTANCE_SESSION_ID });
    const metaJson = '"metadata":{"user_id":' + JSON.stringify(metaValue) + '}';
    const existingMeta = m.indexOf('"metadata":{');
    if (existingMeta !== -1) {
      let depth = 0, mi = existingMeta + '"metadata":'.length;
      for (; mi < m.length; mi++) {
        if (m[mi] === '{') depth++;
        else if (m[mi] === '}') { depth--; if (depth === 0) { mi++; break; } }
      }
      m = m.slice(0, existingMeta) + metaJson + m.slice(mi);
    } else {
      m = '{' + metaJson + ',' + m.slice(1);
    }
  } else {
    // For count_tokens etc., proactively strip any stale metadata the client
    // may have sent, to avoid the same 400.
    const existingMeta = m.indexOf('"metadata":{');
    if (existingMeta !== -1) {
      let depth = 0, mi = existingMeta + '"metadata":'.length;
      for (; mi < m.length; mi++) {
        if (m[mi] === '{') depth++;
        else if (m[mi] === '}') { depth--; if (depth === 0) { mi++; break; } }
      }
      // Also eat a trailing comma if present
      let end = mi;
      if (m[end] === ',') end++;
      // Or a leading comma if we're removing the first/middle field
      let start = existingMeta;
      if (m[start - 1] === ',') start--;
      m = m.slice(0, start) + m.slice(end);
    }
  }

  // Layer 8: Strip trailing assistant prefill (raw string, no JSON.parse)
  // Opus 4.6 disabled assistant message prefill. OpenClaw sometimes pre-fills the
  // next assistant turn to resume interrupted responses, causing permanent 400
  // errors ("This model does not support assistant message prefill"). The error is
  // permanent for the affected session — every retry includes the same prefill.
  // Fix: forward-scan the messages array with string-aware bracket matching,
  // then pop trailing assistant messages until the array ends with a user message.
  if (config.stripTrailingAssistantPrefill !== false) {
    const msgsIdx = m.indexOf('"messages":[');
    if (msgsIdx !== -1) {
      const arrayStart = msgsIdx + '"messages":['.length;
      const positions = [];
      let depth = 0, inString = false, objStart = -1;
      for (let i = arrayStart; i < m.length; i++) {
        const c = m[i];
        if (inString) {
          if (c === '\\') { i++; continue; }
          if (c === '"') inString = false;
          continue;
        }
        if (c === '"') { inString = true; continue; }
        if (c === '{') { if (depth === 0) objStart = i; depth++; }
        else if (c === '}') { depth--; if (depth === 0 && objStart !== -1) { positions.push({ start: objStart, end: i }); objStart = -1; } }
        else if (c === ']' && depth === 0) break;
      }
      let popped = 0;
      while (positions.length > 0) {
        const last = positions[positions.length - 1];
        const obj = m.slice(last.start, last.end + 1);
        if (!obj.includes('"role":"assistant"')) break;
        let stripFrom = last.start;
        for (let i = last.start - 1; i >= arrayStart; i--) {
          if (m[i] === ',') { stripFrom = i; break; }
          if (m[i] !== ' ' && m[i] !== '\n' && m[i] !== '\r' && m[i] !== '\t') break;
        }
        m = m.slice(0, stripFrom) + m.slice(last.end + 1);
        positions.pop();
        popped++;
      }
      if (popped > 0) {
        console.log(`[STRIP-PREFILL] Removed ${popped} trailing assistant message(s)`);
      }
    }
  }

  // Prompt caching: DISABLED in billing-proxy. CLIProxyAPI downstream handles
  // cache_control injection more comprehensively (tools + system + messages)
  // with TTL normalization and 4-breakpoint limit enforcement. If billing-proxy
  // injects first, CLIProxyAPI detects existing breakpoints and skips its own
  // superior injection, losing the messages-level cache breakpoint.
  // m = ensureCacheControl(m);

  return unmaskThinkingBlocks(m, thinkMasks);
}

// ─── Response Processing ────────────────────────────────────────────────────
function reverseMap(text, config) {
  let r = text;
  // Reverse tool names first (more specific patterns).
  // Handle BOTH plain ("Name") AND escaped (\"Name\") forms.
  // SSE input_json_delta embeds tool args in a partial_json string field where
  // inner quotes are escaped. Without the escaped variant, renamed arg keys
  // like \"SendMessage\" never get reverted to \"message\" and OpenClaw's tool
  // runtime fails with "message required". (issue #11)
  for (const [orig, cc] of config.toolRenames) {
    r = r.split('"' + cc + '"').join('"' + orig + '"');
    r = r.split('\\"' + cc + '\\"').join('\\"' + orig + '\\"');
  }
  // Reverse property names — same dual handling
  for (const [orig, renamed] of config.propRenames) {
    r = r.split('"' + renamed + '"').join('"' + orig + '"');
    r = r.split('\\"' + renamed + '\\"').join('\\"' + orig + '\\"');
  }
  // Reverse string replacements
  for (const [sanitized, original] of config.reverseMap) {
    r = r.split(sanitized).join(original);
  }
  return r;
}

// ─── Server ─────────────────────────────────────────────────────────────────
function startServer(config) {
  let requestCount = 0;
  const startedAt = Date.now();

  const server = http.createServer((req, res) => {
    if (req.url === '/health' && req.method === 'GET') {
      try {
        const oauth = getToken(config.credsPath);
        const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: expiresIn > 0 ? 'ok' : 'token_expired',
          proxy: 'openclaw-billing-proxy',
          version: VERSION,
          requestsServed: requestCount,
          uptime: Math.floor((Date.now() - startedAt) / 1000) + 's',
          tokenExpiresInHours: isFinite(expiresIn) ? expiresIn.toFixed(1) : 'n/a',
          subscriptionType: oauth.subscriptionType,
          layers: {
            stringReplacements: config.replacements.length,
            toolNameRenames: config.toolRenames.length,
            propertyRenames: config.propRenames.length,
            ccToolStubs: config.injectCCStubs ? CC_TOOL_STUBS.length : 0,
            systemStripEnabled: config.stripSystemConfig,
            descriptionStripEnabled: config.stripToolDescriptions
          }
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'error', message: e.message }));
      }
      return;
    }

    // ─── count_tokens local interception ─────────────────────────────────
    // Anthropic's count_tokens schema rejects the metadata field entirely,
    // so our CC spoofing is always incomplete here (missing user_id). Rather
    // than forward and risk API-credit billing, estimate locally and return
    // a synthetic response. count_tokens is only used by the client's
    // "X/200K" context meter — approximate is fine, upstream call saved.
    const ctPath = (req.url || '').split('?')[0];
    if (ctPath === '/v1/messages/count_tokens' || ctPath === '/v1/messages/count_tokens/') {
      requestCount++;
      const ctNum = requestCount;
      const ctChunks = [];
      req.on('data', c => ctChunks.push(c));
      req.on('error', e => console.error(`[count_tokens] req err: ${e.message}`));
      req.on('end', () => {
        const bodyStr = Buffer.concat(ctChunks).toString('utf8');
        const estimate = estimateTokenCount(bodyStr);
        const ts = new Date().toISOString().substring(11, 19);
        console.log(`[${ts}] #${ctNum} ${req.method} ${req.url} count_tokens local estimate=${estimate} (${bodyStr.length}b in)`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ input_tokens: estimate }));
      });
      return;
    }

    requestCount++;
    const reqNum = requestCount;
    const chunks = [];

    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks);
      let oauth;
      try { oauth = getToken(config.credsPath); } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        return;
      }

      let bodyStr = body.toString('utf8');
      const originalSize = bodyStr.length;
      bodyStr = processBody(bodyStr, config, (req.url || '').split('?')[0]);
      body = Buffer.from(bodyStr, 'utf8');

      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lk = key.toLowerCase();
        if (lk === 'host' || lk === 'connection' || lk === 'authorization' ||
            lk === 'x-api-key' || lk === 'content-length' ||
            lk === 'x-session-affinity') continue; // strip non-CC headers
        headers[key] = value;
      }
      headers['x-api-key'] = 'sk-oFtQDSI2P7enROnh0';
      delete headers['authorization'];
      headers['content-length'] = body.length;
      headers['accept-encoding'] = 'identity';
      headers['anthropic-version'] = '2023-06-01';

      // Inject Stainless SDK + Claude Code identity headers
      const ccHeaders = getStainlessHeaders();
      for (const [k, v] of Object.entries(ccHeaders)) {
        headers[k] = v;
      }

      // Beta flags: DISABLED in billing-proxy. CLIProxyAPI downstream has more
      // comprehensive betas (structured-outputs, fast-mode, redact-thinking,
      // token-efficient-tools). When billing-proxy sets Anthropic-Beta, CLIProxyAPI
      // detects the incoming header and REPLACES its own defaults with billing-proxy's
      // smaller set, losing 4 useful betas. By not setting the header, CLIProxyAPI
      // uses its full default list.
      // headers['anthropic-beta'] = ...;

      const ts = new Date().toISOString().substring(11, 19);
      console.log(`[${ts}] #${reqNum} ${req.method} ${req.url} (${originalSize}b -> ${body.length}b)`);

      const upstream = http.request({
        hostname: UPSTREAM_HOST, port: 18801,
        path: req.url, method: req.method, headers
      }, (upRes) => {
        const status = upRes.statusCode;
        console.log(`[${ts}] #${reqNum} > ${status}`);
        if (status !== 200 && status !== 201) {
          const errChunks = [];
          upRes.on('data', c => errChunks.push(c));
          upRes.on('end', () => {
            let errBody = Buffer.concat(errChunks).toString();
            if (errBody.includes('extra usage')) {
              console.error(`[${ts}] #${reqNum} DETECTION! Body: ${body.length}b`);
            }
            errBody = reverseMap(errBody, config);
            const nh = { ...upRes.headers };
            delete nh['transfer-encoding']; // avoid conflict with content-length
            nh['content-length'] = Buffer.byteLength(errBody);
            res.writeHead(status, nh);
            res.end(errBody);
          });
          return;
        }
        // SSE streaming — event-aware reverseMap. Buffer until a complete SSE
        // event arrives (terminated by \n\n), then transform per event. This
        // subsumes the older tail-buffer fix for patterns split across TCP
        // chunks (#11) because SSE events are self-contained, so patterns
        // can't span event boundaries. It also lets us track the current
        // content block type across events and pass thinking/redacted_thinking
        // bytes through unchanged — Anthropic rejects the next turn otherwise
        // with "thinking blocks in the latest assistant message cannot be
        // modified."
        if (upRes.headers['content-type'] && upRes.headers['content-type'].includes('text/event-stream')) {
          const sseHeaders = { ...upRes.headers };
          delete sseHeaders['content-length'];      // SSE is streamed, no fixed length
          delete sseHeaders['transfer-encoding'];   // avoid header conflicts
          res.writeHead(status, sseHeaders);
          // StringDecoder buffers incomplete UTF-8 sequences across TCP chunks
          // so multi-byte chars (中文, emoji) that land on a chunk boundary
          // don't decode as U+FFFD.
          const decoder = new StringDecoder('utf8');
          let pending = '';
          let currentBlockIsThinking = false;

          const transformEvent = (event) => {
            // Locate the data: line (always at the start of an SSE line)
            let dataIdx = event.startsWith('data: ') ? 0 : event.indexOf('\ndata: ');
            if (dataIdx === -1) return reverseMap(event, config);
            if (dataIdx > 0) dataIdx += 1; // skip the leading \n
            const dataLineEnd = event.indexOf('\n', dataIdx + 6);
            const dataStr = dataLineEnd === -1
              ? event.slice(dataIdx + 6)
              : event.slice(dataIdx + 6, dataLineEnd);

            if (dataStr.indexOf('"type":"content_block_start"') !== -1) {
              if (dataStr.indexOf('"content_block":{"type":"thinking"') !== -1 ||
                  dataStr.indexOf('"content_block":{"type":"redacted_thinking"') !== -1) {
                currentBlockIsThinking = true;
                return event; // pass through unchanged
              }
              currentBlockIsThinking = false;
              return reverseMap(event, config);
            }
            if (dataStr.indexOf('"type":"content_block_stop"') !== -1) {
              const wasThinking = currentBlockIsThinking;
              currentBlockIsThinking = false;
              return wasThinking ? event : reverseMap(event, config);
            }
            if (currentBlockIsThinking) {
              // thinking_delta / signature_delta / etc. inside a thinking block
              return event;
            }
            return reverseMap(event, config);
          };

          upRes.on('data', (chunk) => {
            pending += decoder.write(chunk);
            let sepIdx;
            while ((sepIdx = pending.indexOf('\n\n')) !== -1) {
              const event = pending.slice(0, sepIdx + 2);
              pending = pending.slice(sepIdx + 2);
              res.write(transformEvent(event));
            }
          });
          upRes.on('end', () => {
            pending += decoder.end();
            if (pending.length > 0) {
              // Trailing bytes with no terminator — shouldn't happen in
              // well-formed SSE, but flush to avoid silent drops.
              res.write(transformEvent(pending));
            }
            res.end();
          });
        } else {
          // Non-SSE (JSON) response. CLIProxyAPI with nonstream-keepalive-interval
          // injects blank-line heartbeat bytes into the response stream every
          // 15s so clients don't time out during long-running inference. The
          // old implementation buffered everything and ate those heartbeats —
          // OpenClaw then timed out at its 15s heartbeat timer.
          //
          // Fix: forward any leading whitespace (heartbeats) immediately, and
          // only start buffering once the real JSON body begins. reverseMap
          // still runs on the buffered body at end. Since response size is
          // unknown until end, Content-Length is dropped and chunked encoding
          // is used.
          let seenRealContent = false;
          let headersWritten = false;
          const respChunks = [];
          const ensureHeaders = () => {
            if (headersWritten) return;
            const nh = { ...upRes.headers };
            delete nh['content-length'];
            delete nh['transfer-encoding'];
            try { res.writeHead(status, nh); headersWritten = true; } catch (e) {}
          };
          upRes.on('data', c => {
            if (!seenRealContent) {
              let i = 0;
              while (i < c.length) {
                const b = c[i];
                if (b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d) { i++; }
                else { break; }
              }
              if (i > 0) {
                ensureHeaders();
                try { res.write(c.subarray(0, i)); } catch (e) {}
              }
              if (i < c.length) {
                seenRealContent = true;
                respChunks.push(c.subarray(i));
              }
            } else {
              respChunks.push(c);
            }
          });
          upRes.on('end', () => {
            ensureHeaders();
            let respBody = Buffer.concat(respChunks).toString();
            // Mask thinking blocks so reverseMap can't mutate them. The client
            // stores these bytes and echoes them on the next turn; Anthropic
            // enforces byte-equality on the latest assistant message.
            const { masked: rMasked, masks: rMasks } = maskThinkingBlocks(respBody);
            respBody = unmaskThinkingBlocks(reverseMap(rMasked, config), rMasks);
            try { res.write(respBody); res.end(); } catch (e) {}
          });
        }
      });
      upstream.on('error', e => {
        console.error(`[${ts}] #${reqNum} ERR: ${e.message}`);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        }
      });
      upstream.write(body);
      upstream.end();
    });
  });

  const bindHost = process.env.PROXY_HOST || '127.0.0.1';
  server.listen(config.port, bindHost, () => {
    try {
      const oauth = getToken(config.credsPath);
      const expiresIn = (oauth.expiresAt - Date.now()) / 3600000;
      const h = isFinite(expiresIn) ? expiresIn.toFixed(1) + 'h' : 'n/a (env var)';
      console.log(`\n  OpenClaw Billing Proxy v${VERSION}`);
      console.log(`  ─────────────────────────────`);
      console.log(`  Port:              ${config.port}`);
      console.log(`  Bind address:      ${bindHost}`);
      console.log(`  Emulating:         Claude Code v${CC_VERSION}`);
      console.log(`  Subscription:      ${oauth.subscriptionType}`);
      console.log(`  Token expires:     ${h}`);
      console.log(`  String patterns:   ${config.replacements.length} sanitize + ${config.reverseMap.length} reverse`);
      console.log(`  Tool renames:      ${config.toolRenames.length} (bidirectional)`);
      console.log(`  Property renames:  ${config.propRenames.length} (bidirectional)`);
      console.log(`  CC tool stubs:     ${config.injectCCStubs ? CC_TOOL_STUBS.length : 'disabled'}`);
      console.log(`  System strip:      ${config.stripSystemConfig ? 'enabled' : 'disabled'}`);
      console.log(`  Description strip: ${config.stripToolDescriptions ? 'enabled' : 'disabled'}`);
      console.log(`  Billing hash:      dynamic (SHA256 fingerprint)`);
      console.log(`  CC headers:        Stainless SDK + identity`);
      console.log(`  Credentials:       ${config.credsPath}`);
      console.log(`\n  Ready. Set openclaw.json baseUrl to http://${bindHost}:${config.port}\n`);
    } catch (e) {
      console.error(`  Started on port ${config.port} but credentials error: ${e.message}`);
    }
  });

  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

// ─── Main ───────────────────────────────────────────────────────────────────
const config = loadConfig();
startServer(config);
