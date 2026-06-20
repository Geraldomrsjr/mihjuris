// /api/analisar-contrato.js
// Vercel Serverless Function — análise jurídica de contratos via Gemini.
// Aditivo: não depende de server.js. Lê GEMINI_API_KEY do ambiente do Vercel.

const MODELO = 'gemini-2.0-flash';

function sanitizar(t) {
  if (typeof t !== 'string') return '';
  return t
    .replace(/<[^>]*>/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .slice(0, 50000)
    .trim();
}

function validarTexto(t) {
  if (!t || typeof t !== 'string') return { ok: false, erro: "Campo 'texto' é obrigatório." };
  if (t.trim().length < 10)        return { ok: false, erro: 'Texto muito curto para análise.' };
  if (t.length > 50000)            return { ok: false, erro: 'Texto excede o limite de 50.000 caracteres.' };
  return { ok: true };
}

async function gemini(prompt) {
  const key = process.env.GEMINI_API_KEY;
  if (!key) throw new Error('GEMINI_API_KEY não configurada nas variáveis de ambiente do Vercel.');

  const resp = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${MODELO}:generateContent?key=${key}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.3, maxOutputTokens: 2000 },
      }),
    }
  );

  const data = await resp.json();
  if (data.error) throw new Error(data.error.message);
  return data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
}

module.exports = async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST')    { res.status(405).json({ ok: false, erro: 'Método não permitido.' }); return; }

  try {
    const body  = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const vTxt  = validarTexto(body.texto);
    if (!vTxt.ok) { res.status(400).json({ ok: false, erro: vTxt.erro }); return; }

    const texto = sanitizar(body.texto);
    const tipo  = sanitizar(body.tipo  || 'contrato').slice(0, 30);
    const papel = sanitizar(body.papel || 'auto').slice(0, 10);
    const papelCtx = (papel && papel !== 'auto')
      ? `\n\nPerspectiva: priorize os interesses do ${papel === 'comprador' ? 'comprador/adquirente' : papel === 'vendedor' ? 'vendedor/alienante' : 'equilíbrio neutro entre as partes'}.`
      : '';

    const prompt = `Você é um advogado sênior brasileiro, especialista em direito civil e contratual. Analise o contrato abaixo de forma técnica, precisa e acessível a leigos. Cite sempre a legislação aplicável (Código Civil, CDC, leis específicas). Nunca invente artigos de lei.

IMPORTANTE: Retorne SOMENTE JSON válido, sem texto antes ou depois, sem blocos de markdown.

Contrato (${tipo}):
${texto.slice(0, 12000)}

Para CADA cláusula problemática (mínimo 5), identifique: número, problema, lei aplicável, risco financeiro estimado em reais, e o ajuste recomendado em português jurídico claro. Classifique a severidade em CRÍTICO, ALERTA ou LEVE.${papelCtx}

Estrutura de saída (responda APENAS com este JSON):
{
  "tipo_contrato": "string",
  "data_assinatura": "YYYY-MM-DD",
  "partes_count": number,
  "risco_geral": "ALTO|MÉDIO|BAIXO",
  "resumo_executivo": { "total_pontos": number, "criticos": number, "alertas": number, "leves": number, "principal_risco": "string curta" },
  "clausulas_problematicas": [
    { "clausula": "Cláusula X", "titulo": "TÍTULO EM MAIÚSCULAS", "severidade": "CRÍTICO|ALERTA|LEVE", "problema": "descrição clara", "lei_aplicavel": "ex: CC art. 422", "risco_reais": "ex: Até R$ 10.000 ou 'Nulidade contratual'", "impacto_partes": "como afeta cada parte", "texto_original": "trecho de até 200 caracteres", "ajuste_recomendado": "como reescrever em português claro", "prioridade": number }
  ],
  "avisos_gerais": [ { "tipo": "LEGAL|FINANCEIRO|PROCESSUAL", "titulo": "string", "descricao": "string" } ],
  "checklist_acoes": [ { "numero": number, "acao": "string", "categoria": "CRÍTICO|ALERTA|LEVE", "prazo": "ex: Antes de assinar" } ],
  "notas_legais": "observações finais; lembrar que nenhum contrato é 100% isento de risco"
}

Regras: prioridade 1 = mais urgente; risco em reais quando possível; linguagem clara mas jurídica; nunca exponha CPF/RG/contas completas.`;

    const raw   = await gemini(prompt);
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('IA não retornou JSON válido. Tente novamente.');

    res.status(200).json({ ok: true, resultado: JSON.parse(match[0]) });
  } catch (e) {
    res.status(500).json({ ok: false, erro: e.message });
  }
};
