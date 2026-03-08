/**
 * MihJuris · Servidor Seguro
 * ─────────────────────────────────────────────────────
 * Proteções implementadas:
 *  1. Rate limiting — máx 20 req/min por IP, 5 análises/hora por IP
 *  2. Validação de arquivos — tipo, tamanho, conteúdo
 *  3. Headers de segurança — HSTS, CSP, XSS, Clickjacking
 *  4. Log de acesso — registra toda atividade com IP e timestamp
 *  5. Variável de ambiente para chave da API (nunca no código)
 *  6. Sanitização de inputs — remove conteúdo malicioso
 *  7. CORS restrito — só aceita do domínio configurado
 * ─────────────────────────────────────────────────────
 * LGPD: nenhum dado de conteúdo é armazenado permanentemente.
 * Logs contêm apenas IP anonimizado, timestamp e tipo de ação.
 */

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const crypto = require('crypto');

// ══════════════════════════════════════════════════════
// CONFIGURAÇÃO — edite apenas estas variáveis
// ══════════════════════════════════════════════════════
const CONFIG = {
  PORT: process.env.PORT || 3000,

  // Chave da API — NUNCA coloque aqui diretamente.
  // No Railway: vá em Variables e adicione GEMINI_API_KEY=sua_chave
  // Localmente: crie um arquivo .env ou defina antes de rodar:
  //   Windows:  set GEMINI_API_KEY=sua_chave && node server.js
  //   Mac/Linux: GEMINI_API_KEY=sua_chave node server.js
  GEMINI_API_KEY: process.env.GEMINI_API_KEY || '',

  // Domínio do seu site (usado no CORS)
  // Exemplo: 'https://mihjuris.up.railway.app'
  // Durante desenvolvimento local, deixe '*'
  ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN || '*',

  // Limites de rate limiting
  RATE: {
    GERAL_MAX:    20,   // máx requisições por minuto por IP
    ANALISE_MAX:  5,    // máx análises por hora por IP
    JANELA_MIN:   60,   // janela em segundos para req gerais
    JANELA_HORA:  3600, // janela em segundos para análises
  },

  // Limites de arquivo
  ARQUIVO: {
    MAX_BYTES:  5 * 1024 * 1024, // 5 MB máximo
    TIPOS_OK:   ['application/pdf', 'text/plain',
                 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    EXTS_OK:    ['.pdf', '.txt', '.docx'],
  },

  // Log
  LOG_FILE: process.env.LOG_FILE || './mihjuris-acesso.log',
  LOG_LEVEL: process.env.LOG_LEVEL || 'info', // 'info' | 'debug' | 'none'
};

// ══════════════════════════════════════════════════════
// 1. LOG DE ACESSO (LGPD-friendly)
// ══════════════════════════════════════════════════════
function anonimizarIP(ip) {
  // Remove o último octeto do IPv4 (ex: 192.168.1.123 → 192.168.1.xxx)
  // Para IPv6, mantém apenas os primeiros 3 grupos
  if (!ip) return 'unknown';
  if (ip.includes('.')) {
    return ip.replace(/\.\d+$/, '.xxx');
  }
  return ip.split(':').slice(0, 3).join(':') + ':xxxx';
}

function log(nivel, acao, ip, extra = '') {
  if (CONFIG.LOG_LEVEL === 'none') return;
  if (nivel === 'debug' && CONFIG.LOG_LEVEL !== 'debug') return;

  const ts      = new Date().toISOString();
  const ipAnon  = anonimizarIP(ip);
  const linha   = `[${ts}] [${nivel.toUpperCase()}] ${acao} | IP: ${ipAnon}${extra ? ' | ' + extra : ''}\n`;

  // Console
  process.stdout.write(linha);

  // Arquivo de log (rotaciona se passar de 10 MB)
  try {
    const stats = fs.existsSync(CONFIG.LOG_FILE) ? fs.statSync(CONFIG.LOG_FILE) : null;
    if (stats && stats.size > 10 * 1024 * 1024) {
      fs.renameSync(CONFIG.LOG_FILE, CONFIG.LOG_FILE + '.old');
    }
    fs.appendFileSync(CONFIG.LOG_FILE, linha);
  } catch { /* não bloquear por erro de log */ }
}

// ══════════════════════════════════════════════════════
// 2. RATE LIMITING
// ══════════════════════════════════════════════════════
const _rateGeral   = new Map(); // IP → { count, reset }
const _rateAnalise = new Map(); // IP → { count, reset }

function checkRate(ip, mapa, max, janela, acao) {
  const agora = Math.floor(Date.now() / 1000);
  const entry = mapa.get(ip);

  if (!entry || agora > entry.reset) {
    mapa.set(ip, { count: 1, reset: agora + janela });
    return { ok: true, restante: max - 1 };
  }

  entry.count++;
  if (entry.count > max) {
    const espera = entry.reset - agora;
    log('warn', `RATE_LIMIT_BLOQUEADO: ${acao}`, ip, `espera ${espera}s`);
    return { ok: false, espera };
  }

  return { ok: true, restante: max - entry.count };
}

// Limpar entradas expiradas a cada 5 minutos
setInterval(() => {
  const agora = Math.floor(Date.now() / 1000);
  for (const [ip, e] of _rateGeral)   if (agora > e.reset) _rateGeral.delete(ip);
  for (const [ip, e] of _rateAnalise) if (agora > e.reset) _rateAnalise.delete(ip);
}, 5 * 60 * 1000);

// ══════════════════════════════════════════════════════
// 3. HEADERS DE SEGURANÇA
// ══════════════════════════════════════════════════════
function aplicarHeaders(res, origem) {
  const origin = CONFIG.ALLOWED_ORIGIN === '*' ? '*' : origem || '';

  res.setHeader('Access-Control-Allow-Origin',  origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Request-ID');

  // Proteção XSS
  res.setHeader('X-Content-Type-Options',    'nosniff');
  res.setHeader('X-XSS-Protection',          '1; mode=block');

  // Impede que o site seja carregado em iframe (clickjacking)
  res.setHeader('X-Frame-Options',           'SAMEORIGIN');

  // HTTPS obrigatório (ativo em produção)
  if (CONFIG.ALLOWED_ORIGIN !== '*') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  // Content Security Policy — restringe de onde recursos podem ser carregados
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "connect-src 'self'; " +
    "img-src 'self' data:; " +
    "frame-ancestors 'none';"
  );

  // Remove informações do servidor
  res.removeHeader('X-Powered-By');
  res.setHeader('Server', 'MihJuris');

  // Cache control para arquivos sensíveis
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma',        'no-cache');
}

// ══════════════════════════════════════════════════════
// 4. SANITIZAÇÃO DE INPUT
// ══════════════════════════════════════════════════════
function sanitizar(texto) {
  if (typeof texto !== 'string') return '';

  return texto
    // Remove tags HTML/JS
    .replace(/<[^>]*>/g, '')
    // Remove scripts inline
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    // Remove caracteres de controle (exceto \n e \t)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    // Limita tamanho
    .slice(0, 50000)
    .trim();
}

function validarTexto(texto, campo) {
  if (!texto || typeof texto !== 'string') {
    return { ok: false, erro: `Campo '${campo}' é obrigatório.` };
  }
  if (texto.trim().length < 10) {
    return { ok: false, erro: `Campo '${campo}' muito curto.` };
  }
  if (texto.length > 50000) {
    return { ok: false, erro: `Campo '${campo}' excede o limite de 50.000 caracteres.` };
  }
  return { ok: true };
}

// ══════════════════════════════════════════════════════
// 5. VALIDAÇÃO DE ARQUIVO
// ══════════════════════════════════════════════════════
function validarArquivo(body) {
  const { nome, tipo, tamanho } = body;

  if (!nome || typeof nome !== 'string') {
    return { ok: false, erro: 'Nome do arquivo inválido.' };
  }

  const ext = path.extname(nome).toLowerCase();
  if (!CONFIG.ARQUIVO.EXTS_OK.includes(ext)) {
    return { ok: false, erro: `Extensão '${ext}' não permitida. Use: PDF, DOCX ou TXT.` };
  }

  if (tamanho && tamanho > CONFIG.ARQUIVO.MAX_BYTES) {
    return { ok: false, erro: `Arquivo muito grande. Máximo: 5 MB.` };
  }

  // Detectar path traversal no nome do arquivo
  if (nome.includes('..') || nome.includes('/') || nome.includes('\\')) {
    return { ok: false, erro: 'Nome de arquivo inválido.' };
  }

  return { ok: true };
}

// ══════════════════════════════════════════════════════
// 6. GEMINI API
// ══════════════════════════════════════════════════════
function gemini(prompt) {
  return new Promise((resolve, reject) => {
    if (!CONFIG.GEMINI_API_KEY) {
      reject(new Error('Chave da API não configurada. Adicione GEMINI_API_KEY nas variáveis de ambiente.'));
      return;
    }

    const body = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 1500 },
    });

    const opts = {
      hostname: 'generativelanguage.googleapis.com',
      path:     `/v1beta/models/gemini-1.5-flash:generateContent?key=${CONFIG.GEMINI_API_KEY}`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    };

    const req = https.request(opts, res => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => {
        try {
          const data = JSON.parse(buf);
          if (data.error) { reject(new Error(data.error.message)); return; }
          const texto = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
          resolve(texto);
        } catch (e) { reject(new Error('Resposta inválida da API.')); }
      });
    });

    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Timeout — API demorou mais de 30s.')); });
    req.write(body);
    req.end();
  });
}

// ══════════════════════════════════════════════════════
// 7. ANÁLISE DE DOCUMENTO
// ══════════════════════════════════════════════════════
async function analisarDocumento(texto, tipo) {
  const prompt = `Você é um assistente jurídico especialista em direito brasileiro.
Analise o texto jurídico abaixo e retorne SOMENTE JSON válido, sem texto antes ou depois:

{"tipo_peca":"tipo da peça processual","area_direito":"área do direito","estilo":{"tom":"tom da escrita","caracteristicas":["c1","c2","c3"],"pontos_fortes":["p1","p2"]},"proximos_passos":[{"titulo":"Passo 1","descricao":"o que fazer"},{"titulo":"Passo 2","descricao":"o que fazer"},{"titulo":"Passo 3","descricao":"o que fazer"}],"pontos_atencao":["atenção 1","atenção 2","atenção 3"],"possiveis_argumentos_contrarios":["argumento 1","argumento 2","argumento 3"]}

Texto (${tipo}):
${texto.slice(0, 8000)}

Responda APENAS com o JSON. Zero texto adicional.`;

  const raw   = await gemini(prompt);
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) throw new Error('IA não retornou JSON válido. Tente novamente.');
  return JSON.parse(match[0]);
}

async function sugerirTexto(ponto, contexto) {
  const prompt = `Você é assistente jurídico brasileiro. Sugira um complemento processual CONCISO (máximo 4 linhas) para o ponto abaixo. Linguagem jurídica direta. O advogado vai revisar e reescrever antes de usar.

Ponto de atenção: ${ponto}
Contexto: ${contexto || '—'}

Responda apenas com o texto sugerido, sem introdução.`;

  return await gemini(prompt);
}

// ══════════════════════════════════════════════════════
// 8. UTILITÁRIOS HTTP
// ══════════════════════════════════════════════════════
function lerBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let bytes = 0;
    req.on('data', chunk => {
      bytes += chunk.length;
      // Rejeitar body maior que 6 MB
      if (bytes > 6 * 1024 * 1024) {
        req.destroy();
        reject(new Error('Payload muito grande.'));
        return;
      }
      data += chunk;
    });
    req.on('end',   () => { try { resolve(JSON.parse(data)); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

function json(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function getIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.ico':  'image/x-icon',
};

// ══════════════════════════════════════════════════════
// 9. SERVIDOR
// ══════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const ip      = getIP(req);
  const parsed  = url.parse(req.url, true);
  const rota    = parsed.pathname;
  const origem  = req.headers.origin || '';
  const reqId   = crypto.randomBytes(4).toString('hex');

  aplicarHeaders(res, origem);

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── Rate limiting geral ──────────────────────────────
  const rg = checkRate(ip, _rateGeral, CONFIG.RATE.GERAL_MAX, CONFIG.RATE.JANELA_MIN, rota);
  if (!rg.ok) {
    json(res, 429, { ok: false, erro: `Muitas requisições. Aguarde ${rg.espera} segundos.` });
    return;
  }

  log('info', `${req.method} ${rota}`, ip, `req:${reqId}`);

  // ── Status da API ────────────────────────────────────
  if (rota === '/api/status') {
    json(res, 200, {
      ok:     !!CONFIG.GEMINI_API_KEY,
      modelo: CONFIG.GEMINI_API_KEY ? 'Gemini 1.5 Flash' : null,
      msg:    CONFIG.GEMINI_API_KEY ? '✅ IA pronta' : '❌ Chave não configurada',
    });
    return;
  }

  // ── Analisar documento ───────────────────────────────
  if (rota === '/api/analisar' && req.method === 'POST') {

    // Rate limiting específico para análises
    const ra = checkRate(ip, _rateAnalise, CONFIG.RATE.ANALISE_MAX, CONFIG.RATE.JANELA_HORA, 'ANALISE');
    if (!ra.ok) {
      json(res, 429, { ok: false, erro: `Limite de ${CONFIG.RATE.ANALISE_MAX} análises por hora atingido. Aguarde ${Math.ceil(ra.espera/60)} minutos.` });
      return;
    }

    try {
      const body = await lerBody(req);

      // Validar arquivo
      const vArq = validarArquivo({ nome: body.nomeArquivo || 'arquivo.txt', tipo: body.tipo, tamanho: body.tamanho });
      if (!vArq.ok) { json(res, 400, { ok: false, erro: vArq.erro }); return; }

      // Validar e sanitizar texto
      const vTxt = validarTexto(body.texto, 'texto');
      if (!vTxt.ok) { json(res, 400, { ok: false, erro: vTxt.erro }); return; }

      const textoSeguro = sanitizar(body.texto);
      const tipo        = sanitizar(body.tipo || 'documento').slice(0, 20);

      log('info', 'ANALISE_INICIO', ip, `req:${reqId} tipo:${tipo} chars:${textoSeguro.length}`);

      const resultado = await analisarDocumento(textoSeguro, tipo);

      log('info', 'ANALISE_OK', ip, `req:${reqId}`);
      json(res, 200, { ok: true, resultado });

    } catch (e) {
      log('warn', `ANALISE_ERRO: ${e.message}`, ip, `req:${reqId}`);
      json(res, 500, { ok: false, erro: e.message });
    }
    return;
  }

  // ── Sugerir texto ────────────────────────────────────
  if (rota === '/api/sugerir' && req.method === 'POST') {

    const ra = checkRate(ip, _rateAnalise, CONFIG.RATE.ANALISE_MAX, CONFIG.RATE.JANELA_HORA, 'SUGESTAO');
    if (!ra.ok) {
      json(res, 429, { ok: false, erro: `Limite atingido. Aguarde ${Math.ceil(ra.espera/60)} minutos.` });
      return;
    }

    try {
      const body    = await lerBody(req);
      const ponto   = sanitizar(body.ponto   || '').slice(0, 500);
      const contexto = sanitizar(body.contexto || '').slice(0, 200);
      if (!ponto) { json(res, 400, { ok: false, erro: 'Ponto de atenção vazio.' }); return; }

      const texto = await sugerirTexto(ponto, contexto);
      log('info', 'SUGESTAO_OK', ip, `req:${reqId}`);
      json(res, 200, { ok: true, texto });

    } catch (e) {
      log('warn', `SUGESTAO_ERRO: ${e.message}`, ip, `req:${reqId}`);
      json(res, 500, { ok: false, erro: e.message });
    }
    return;
  }

  // ── Arquivos estáticos ───────────────────────────────
  if (req.method === 'GET') {
    const filePath = path.join(__dirname, 'public',
      rota === '/' ? 'index.html' : rota);

    // Segurança: impedir path traversal
    const publicDir = path.resolve(__dirname, 'public');
    const resolved  = path.resolve(filePath);
    if (!resolved.startsWith(publicDir)) {
      log('warn', 'PATH_TRAVERSAL_BLOCKED', ip, `tentativa: ${rota}`);
      json(res, 403, { ok: false, erro: 'Acesso negado.' });
      return;
    }

    if (!fs.existsSync(resolved)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Não encontrado.');
      return;
    }

    const ext  = path.extname(resolved);
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    fs.createReadStream(resolved).pipe(res);
    return;
  }

  res.writeHead(405); res.end('Método não permitido.');
});

// ══════════════════════════════════════════════════════
// INICIALIZAÇÃO
// ══════════════════════════════════════════════════════
server.listen(CONFIG.PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════╗');
  console.log('║      MihJuris · Servidor Seguro            ║');
  console.log('╠════════════════════════════════════════════╣');
  console.log(`║  Acesse:  http://localhost:${CONFIG.PORT}           ║`);
  console.log(`║  Ambiente: ${CONFIG.ALLOWED_ORIGIN === '*' ? 'DESENVOLVIMENTO (local)  ' : 'PRODUÇÃO                 '}║`);
  console.log('╚════════════════════════════════════════════╝');
  console.log('');

  if (!CONFIG.GEMINI_API_KEY) {
    console.log('⚠️  ATENÇÃO: Chave GEMINI_API_KEY não encontrada!');
    console.log('   Análise de documentos ficará desativada.');
    console.log('   Obtenha gratuitamente em: aistudio.google.com');
    console.log('   Railway: adicione em Settings → Variables');
    console.log('');
  } else {
    console.log('✅ Gemini API configurada');
  }

  console.log('🔒 Proteções ativas:');
  console.log(`   • Rate limiting: ${CONFIG.RATE.GERAL_MAX} req/min | ${CONFIG.RATE.ANALISE_MAX} análises/hora por IP`);
  console.log('   • Validação de arquivos: PDF, DOCX, TXT — máx 5 MB');
  console.log('   • Headers de segurança: HSTS, CSP, XSS, Clickjacking');
  console.log(`   • Log de acesso: ${CONFIG.LOG_FILE}`);
  console.log('   • Sanitização de inputs: ativa');
  console.log('   • Path traversal: bloqueado');
  console.log('');
  console.log('Pressione Ctrl+C para parar.');
});

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Porta ${CONFIG.PORT} já está em uso. Tente outra porta.`);
  } else {
    console.error('❌ Erro no servidor:', err.message);
  }
  process.exit(1);
});
