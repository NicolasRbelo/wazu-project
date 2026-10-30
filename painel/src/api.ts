import type {
  Alerta,
  Analise,
  Bloqueio,
  FeedbackItem,
  PedidoRevisao,
  Reputacao,
  UsoFeedback,
} from "./tipos";

export class ErroApi extends Error {
  constructor(
    readonly status: number,
    readonly detalhe: string | null,
  ) {
    super(detalhe ?? `HTTP ${status}`);
  }
}

/** Falha de rede: a API não respondeu (fora do ar, porta errada). */
export class ErroRede extends Error {}

async function pedir<T>(caminho: string, token: string, init: RequestInit = {}): Promise<T> {
  let resposta: Response;
  try {
    resposta = await fetch(caminho, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init.body ? { "Content-Type": "application/json" } : {}),
      },
    });
  } catch {
    throw new ErroRede();
  }
  if (!resposta.ok) {
    let detalhe: string | null = null;
    try {
      const corpo = await resposta.json();
      // FastAPI: detail é texto nos nossos erros e lista nos erros de validação.
      if (typeof corpo?.detail === "string") detalhe = corpo.detail;
      else if (Array.isArray(corpo?.detail) && typeof corpo.detail[0]?.msg === "string") {
        detalhe = corpo.detail[0].msg.replace(/^Value error, /, "");
      }
    } catch {
      // corpo sem JSON: fica só o status
    }
    throw new ErroApi(resposta.status, detalhe);
  }
  return (await resposta.json()) as T;
}

const json = (corpo: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(corpo) });

export const api = {
  listarAlertas: (token: string) => pedir<Alerta[]>("/api/alertas?limite=200", token),

  reputacao: (token: string, alertaId: number) =>
    pedir<Reputacao>(`/api/alertas/${alertaId}/reputacao`, token),

  /** null quando o alerta ainda não tem análise. */
  analise: async (token: string, alertaId: number): Promise<Analise | null> => {
    try {
      return await pedir<Analise>(`/api/alertas/${alertaId}/analise`, token);
    } catch (erro) {
      if (erro instanceof ErroApi && erro.status === 404) return null;
      throw erro;
    }
  },

  analisar: (token: string, alertaId: number, refazer = false) =>
    pedir<Analise>(`/api/alertas/${alertaId}/analise${refazer ? "?refazer=true" : ""}`, token, {
      method: "POST",
    }),

  revisar: (token: string, alertaId: number, pedido: PedidoRevisao) =>
    pedir<Analise>(`/api/alertas/${alertaId}/revisao`, token, json(pedido)),

  /** null quando o IP ainda não foi bloqueado no agente. */
  bloqueio: async (token: string, alertaId: number): Promise<Bloqueio | null> => {
    try {
      return await pedir<Bloqueio>(`/api/alertas/${alertaId}/bloqueio`, token);
    } catch (erro) {
      if (erro instanceof ErroApi && erro.status === 404) return null;
      throw erro;
    }
  },

  bloquear: (token: string, alertaId: number) =>
    pedir<Bloqueio>(`/api/alertas/${alertaId}/bloqueio`, token, { method: "POST" }),

  listarFeedback: (token: string) => pedir<FeedbackItem[]>("/api/feedback", token),

  alterarUso: (token: string, feedbackId: string, uso: UsoFeedback) =>
    pedir<FeedbackItem>(`/api/feedback/${feedbackId}`, token, {
      method: "PATCH",
      body: JSON.stringify({ uso }),
    }),
};
