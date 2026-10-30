// Espelho dos schemas da API (app/schemas.py). Os valores ficam em português, como a API devolve.

export type Classificacao = "verdadeiro_positivo" | "falso_positivo" | "inconclusivo";
export type Severidade = "baixa" | "media" | "alta" | "critica";
export type Acao = "bloquear_ip" | "investigar" | "monitorar" | "descartar";
export type Revisao = "pendente" | "aprovada" | "corrigida" | "descartada";
export type Decisao = Exclude<Revisao, "pendente">;
export type Importancia = "alta" | "media" | "baixa";
export type UsoFeedback = "exemplo" | "quarentena";

export const CLASSIFICACOES: Classificacao[] = ["verdadeiro_positivo", "falso_positivo", "inconclusivo"];
export const SEVERIDADES: Severidade[] = ["baixa", "media", "alta", "critica"];
export const ACOES: Acao[] = ["bloquear_ip", "investigar", "monitorar", "descartar"];

export interface ResumoAnalise {
  id: number;
  revisao: Revisao;
  classificacao: Classificacao;
  severidade: Severidade;
  acao_sugerida: Acao;
  indicios_manipulacao: boolean;
}

export interface ResumoIncidente {
  id: number;
  total: number;
  nivel_max: number;
  primeiro_em: string;
  ultimo_em: string;
  decisao: Decisao | null;
}

export interface Alerta {
  id: number;
  wazuh_id: string;
  rule_id: string;
  rule_level: number;
  rule_description: string;
  agent_name: string | null;
  srcip: string | null;
  full_log: string | null;
  recebido_em: string;
  analise: ResumoAnalise | null;
  incidente: ResumoIncidente | null;
}

export interface Correcao {
  classificacao: Classificacao;
  severidade: Severidade;
  acao_sugerida: Acao;
}

export interface Sugestao extends Correcao {
  confianca: number;
  resumo: string;
  justificativa: string;
  tecnicas_mitre: string[];
  indicios_manipulacao: boolean;
}

export interface Analise {
  id: number;
  alerta_id: number;
  modelo: string;
  sugestao: Sugestao;
  sugestao_ia: Sugestao;
  ajustes: string[];
  revisao: Revisao;
  criada_em: string;
  revisado_em: string | null;
  correcao: Correcao | null;
  nota: string | null;
}

export interface ResultadoFonte {
  status: "ok" | "nao_configurado" | "limite_excedido" | "erro";
  em_cache: boolean;
  consultado_em: string | null;
  dados: Record<string, unknown> | null;
  erro: string | null;
}

export interface Reputacao {
  ip: string | null;
  publico: boolean;
  fontes: Record<string, ResultadoFonte>;
}

export interface FeedbackItem {
  id: string;
  criado_em: string;
  alerta_id: number;
  analise_id: number;
  regra: { id: string; nivel: number; descricao: string };
  sugestao: Correcao;
  decisao: Decisao;
  final: Correcao;
  nota: string | null;
  importancia: Importancia;
  motivo_importancia: string;
  uso: UsoFeedback;
  motivo_uso: string;
}

export interface Bloqueio {
  id: number;
  alerta_id: number;
  ip: string;
  agente_id: string;
  sucesso: boolean;
  detalhe: string;
  executado_em: string;
}

/** A ação que vale depois da revisão: a corrigida pelo analista ou a sugestão final aprovada. */
export function acaoDecidida(analise: Analise): Acao | null {
  if (analise.revisao === "aprovada") return analise.sugestao.acao_sugerida;
  if (analise.revisao === "corrigida") return analise.correcao?.acao_sugerida ?? null;
  return null;
}

export interface PedidoRevisao {
  decisao: Decisao;
  correcao?: Correcao;
  nota?: string;
}

export function resumoDe(analise: Analise): ResumoAnalise {
  return {
    id: analise.id,
    revisao: analise.revisao,
    classificacao: analise.sugestao.classificacao,
    severidade: analise.sugestao.severidade,
    acao_sugerida: analise.sugestao.acao_sugerida,
    indicios_manipulacao: analise.sugestao.indicios_manipulacao,
  };
}

export function estaPendente(alerta: Alerta): boolean {
  // Decidir um alerta decide o incidente inteiro.
  if (alerta.incidente?.decisao) return false;
  return alerta.analise === null || alerta.analise.revisao === "pendente";
}

/**
 * Uma faixa por incidente. O representante é o alerta já analisado mais recente
 * ou, sem análise, o mais recente. A lista chega do mais recente para o mais antigo,
 * e a faixa fica na posição do alerta mais novo do incidente.
 */
export function agruparPorIncidente(alertas: Alerta[]): Alerta[] {
  const grupos = new Map<string, Alerta>();
  for (const alerta of alertas) {
    const chave = alerta.incidente ? `i${alerta.incidente.id}` : `a${alerta.id}`;
    const atual = grupos.get(chave);
    if (!atual || (!atual.analise && alerta.analise)) grupos.set(chave, alerta);
  }
  return [...grupos.values()];
}
