import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { CHAVE_IDIOMA, gravar, ler } from "./armazenamento";

export type Idioma = "pt" | "en";

const pt = {
  fila: "Fila",
  feedback: "Feedback da IA",
  navegacao: "Navegação principal",
  buscar: "Buscar por IP, regra ou agente",
  buscarDica: "IP, regra ou agente",
  apiConectada: "API conectada",
  apiFora: "API sem resposta",
  idioma: "Idioma",
  sair: "Sair",
  pendentes: "Pendentes",
  decididos: "Decididos",
  faixas: "{n} faixas",
  nivel: "nível",
  origem: "origem",
  semAnalise: "sem análise",
  manipulacao: "manipulação",
  filaVazia: "Fila limpa: nenhum alerta pendente.",
  filaVaziaDica: "Para gerar um no laboratório: python lab/simular_ataque.py",
  nadaDecidido: "Nenhuma decisão ainda.",
  semResultados: "Nenhuma faixa bate com a busca.",
  selecione: "Escolha uma faixa no trilho para abrir o alerta.",
  voltar: "Voltar à fila",
  recebido: "recebido {quando} UTC",
  incidente: "incidente: {n} alertas, {inicio} a {fim} UTC",
  decisaoIncidente: "Vale para os {n} alertas do incidente.",
  regra: "regra {id}",
  agente: "agente {nome}",
  evidencia: "Evidência",
  naoConfiavel: "Dado não confiável: escrito por quem gerou o evento",
  semLog: "O alerta chegou sem log original.",
  reputacao: "Reputação do IP",
  consultarReputacao: "Consultar reputação",
  reputacaoDica: "AbuseIPDB e VirusTotal, guardado em cache por 24 h.",
  ipNaoPublico: "IP não público: não consultado, para não expor endereços internos a terceiros.",
  semIp: "Alerta sem IP de origem.",
  denuncias: "{n} denúncias",
  naWhitelist: "na whitelist",
  foraWhitelist: "fora da whitelist",
  tor: "saída Tor",
  motoresMaliciosos: "motores maliciosos",
  suspeitos: "{n} suspeitos",
  doCache: "do cache",
  fonteNaoConfigurada: "chave não configurada no .env",
  fonteLimite: "limite de consultas atingido",
  fonteErro: "consulta falhou ({erro})",
  sugestao: "Sugestão: IA x final",
  analisar: "Analisar com IA",
  analisarDica: "Leva cerca de 7 s e usa a cota do Gemini. Só roda quando você pede.",
  semAnaliseTexto: "Este alerta ainda não foi analisado. Use Analisar com IA na barra abaixo, ou a tecla I.",
  analisando: "Analisando…",
  refazer: "Refazer análise",
  iaDisse: "IA disse",
  final: "Final",
  analista: "analista",
  classificacao: "Classificação",
  severidade: "Severidade",
  acao: "Ação",
  confianca: "confiança {n}%",
  ajustes: "Ajustes das políticas",
  semAjustes: "Nenhum: as políticas mantiveram a sugestão da IA.",
  manipulacaoAviso: "Indício de manipulação: os dados tentam instruir a IA. Trate o alerta como mais suspeito.",
  modelo: "{modelo}, {quando} UTC",
  aprovar: "Aprovar",
  corrigir: "Corrigir",
  descartar: "Descartar",
  proximo: "Próximo",
  anterior: "Anterior",
  comTecla: "{acao} (tecla {tecla})",
  decidirDica: "Analise o alerta antes de decidir.",
  nota: "Nota",
  notaAjuda: "Explique a decisão em pelo menos {n} caracteres. Ela vira feedback para a IA.",
  notaCurta: "A nota precisa de pelo menos {n} caracteres.",
  correcaoIgual: "A correção não muda nada. Use Aprovar.",
  salvarCorrecao: "Salvar correção",
  confirmarDescarte: "Descartar alerta",
  cancelar: "Cancelar",
  decididoEm: "{quando} UTC",
  notaAnalista: "Nota do analista",
  bloquearIp: "Bloquear {ip} no agente",
  confirmarBloqueio: "Confirmar bloqueio de {ip} em {agente}",
  bloqueioDica: "Executa o firewall-drop do Wazuh na máquina atacada. Fica até ser removido lá.",
  bloqueando: "Bloqueando…",
  bloqueado: "{ip} bloqueado em {agente}, {quando} UTC",
  erroGenerico: "Algo falhou (HTTP {status}). Tente de novo.",
  erroRede: "A API não respondeu. Ela está rodando? python run.py",
  conectarTitulo: "Conectar à API",
  conectarTexto: "Cole o valor de API_TOKEN do arquivo .env. Ele fica só nesta aba e some quando ela fecha.",
  token: "Token da API",
  conectar: "Conectar",
  conectando: "Conectando…",
  tokenRecusado: "A API recusou esse token.",
  sessaoExpirada: "A API recusou o token salvo. Conecte de novo.",
  feedbackTexto: "Cada decisão vira um registro. A IA só aprende com os exemplos; a quarentena segura feedback que pode ensiná-la a errar.",
  todos: "Todos",
  quarentena: "Quarentena",
  exemplos: "Exemplos",
  feedbackVazio: "Nenhum feedback ainda. Cada decisão na fila cria um.",
  filtroVazio: "Nada neste filtro.",
  liberar: "Liberar para a IA",
  quarentenar: "Pôr em quarentena",
  importancia: "importância",
  carregando: "Carregando…",
  atalhos: "Atalhos",
};

export type Chave = keyof typeof pt;

const en: Record<Chave, string> = {
  fila: "Queue",
  feedback: "AI feedback",
  navegacao: "Main navigation",
  buscar: "Search by IP, rule or agent",
  buscarDica: "IP, rule or agent",
  apiConectada: "API connected",
  apiFora: "API not responding",
  idioma: "Language",
  sair: "Sign out",
  pendentes: "Pending",
  decididos: "Decided",
  faixas: "{n} strips",
  nivel: "level",
  origem: "source",
  semAnalise: "not analyzed",
  manipulacao: "manipulation",
  filaVazia: "Queue clear: no pending alerts.",
  filaVaziaDica: "To generate one in the lab: python lab/simular_ataque.py",
  nadaDecidido: "No decisions yet.",
  semResultados: "No strip matches the search.",
  selecione: "Pick a strip on the rack to open the alert.",
  voltar: "Back to queue",
  recebido: "received {quando} UTC",
  incidente: "incident: {n} alerts, {inicio} to {fim} UTC",
  decisaoIncidente: "Applies to all {n} alerts in the incident.",
  regra: "rule {id}",
  agente: "agent {nome}",
  evidencia: "Evidence",
  naoConfiavel: "Untrusted data: written by whoever caused the event",
  semLog: "The alert arrived without its original log.",
  reputacao: "IP reputation",
  consultarReputacao: "Check reputation",
  reputacaoDica: "AbuseIPDB and VirusTotal, cached for 24 h.",
  ipNaoPublico: "Non-public IP: not looked up, so internal addresses never reach third parties.",
  semIp: "Alert has no source IP.",
  denuncias: "{n} reports",
  naWhitelist: "whitelisted",
  foraWhitelist: "not whitelisted",
  tor: "Tor exit",
  motoresMaliciosos: "malicious engines",
  suspeitos: "{n} suspicious",
  doCache: "cached",
  fonteNaoConfigurada: "key not set in .env",
  fonteLimite: "lookup limit reached",
  fonteErro: "lookup failed ({erro})",
  sugestao: "Suggestion: AI vs final",
  analisar: "Analyze with AI",
  analisarDica: "Takes about 7 s and uses Gemini quota. Runs only when you ask.",
  semAnaliseTexto: "This alert has not been analyzed yet. Use Analyze with AI in the bar below, or the I key.",
  analisando: "Analyzing…",
  refazer: "Analyze again",
  iaDisse: "AI said",
  final: "Final",
  analista: "analyst",
  classificacao: "Classification",
  severidade: "Severity",
  acao: "Action",
  confianca: "{n}% confidence",
  ajustes: "Policy adjustments",
  semAjustes: "None: the policies kept the AI suggestion.",
  manipulacaoAviso: "Signs of manipulation: the data tries to instruct the AI. Treat the alert as more suspicious.",
  modelo: "{modelo}, {quando} UTC",
  aprovar: "Approve",
  corrigir: "Correct",
  descartar: "Discard",
  proximo: "Next",
  anterior: "Previous",
  comTecla: "{acao} ({tecla} key)",
  decidirDica: "Analyze the alert before deciding.",
  nota: "Note",
  notaAjuda: "Explain the decision in at least {n} characters. It becomes feedback for the AI.",
  notaCurta: "The note needs at least {n} characters.",
  correcaoIgual: "The correction changes nothing. Use Approve.",
  salvarCorrecao: "Save correction",
  confirmarDescarte: "Discard alert",
  cancelar: "Cancel",
  decididoEm: "{quando} UTC",
  notaAnalista: "Analyst note",
  bloquearIp: "Block {ip} on the agent",
  confirmarBloqueio: "Confirm blocking {ip} on {agente}",
  bloqueioDica: "Runs Wazuh's firewall-drop on the attacked machine. Stays until removed there.",
  bloqueando: "Blocking…",
  bloqueado: "{ip} blocked on {agente}, {quando} UTC",
  erroGenerico: "Something failed (HTTP {status}). Try again.",
  erroRede: "The API did not answer. Is it running? python run.py",
  conectarTitulo: "Connect to the API",
  conectarTexto: "Paste the API_TOKEN value from the .env file. It stays in this tab only and is gone when the tab closes.",
  token: "API token",
  conectar: "Connect",
  conectando: "Connecting…",
  tokenRecusado: "The API rejected this token.",
  sessaoExpirada: "The API rejected the saved token. Connect again.",
  feedbackTexto: "Every decision becomes a record. The AI learns only from examples; quarantine holds back feedback that could teach it to be wrong.",
  todos: "All",
  quarentena: "Quarantine",
  exemplos: "Examples",
  feedbackVazio: "No feedback yet. Every decision on the queue creates one.",
  filtroVazio: "Nothing in this filter.",
  liberar: "Release to the AI",
  quarentenar: "Quarantine",
  importancia: "importance",
  carregando: "Loading…",
  atalhos: "Shortcuts",
};

// Rótulos dos valores da API: [português, inglês].
const ROTULOS = {
  classificacao: {
    verdadeiro_positivo: ["Verdadeiro positivo", "True positive"],
    falso_positivo: ["Falso positivo", "False positive"],
    inconclusivo: ["Inconclusivo", "Inconclusive"],
  },
  severidade: {
    baixa: ["Baixa", "Low"],
    media: ["Média", "Medium"],
    alta: ["Alta", "High"],
    critica: ["Crítica", "Critical"],
  },
  acao: {
    bloquear_ip: ["Bloquear IP", "Block IP"],
    investigar: ["Investigar", "Investigate"],
    monitorar: ["Monitorar", "Monitor"],
    descartar: ["Descartar", "Discard"],
  },
  carimbo: {
    pendente: ["Pendente", "Pending"],
    aprovada: ["Aprovado", "Approved"],
    corrigida: ["Corrigido", "Corrected"],
    descartada: ["Descartado", "Discarded"],
  },
  importancia: {
    alta: ["Alta", "High"],
    media: ["Média", "Medium"],
    baixa: ["Baixa", "Low"],
  },
  uso: {
    exemplo: ["Exemplo", "Example"],
    quarentena: ["Quarentena", "Quarantine"],
  },
} as const;

export type Grupo = keyof typeof ROTULOS;

interface ContextoIdioma {
  idioma: Idioma;
  trocar: (idioma: Idioma) => void;
  t: (chave: Chave, vars?: Record<string, string | number>) => string;
  rotulo: (grupo: Grupo, valor: string) => string;
}

const Contexto = createContext<ContextoIdioma | null>(null);

function idiomaInicial(): Idioma {
  const salvo = ler("local", CHAVE_IDIOMA);
  if (salvo === "pt" || salvo === "en") return salvo;
  return navigator.language.toLowerCase().startsWith("pt") ? "pt" : "en";
}

export function ProvedorIdioma({ children }: { children: ReactNode }) {
  const [idioma, setIdioma] = useState<Idioma>(idiomaInicial);

  useEffect(() => {
    document.documentElement.lang = idioma === "pt" ? "pt-BR" : "en";
  }, [idioma]);

  const trocar = useCallback((novo: Idioma) => {
    setIdioma(novo);
    gravar("local", CHAVE_IDIOMA, novo);
  }, []);

  const valor = useMemo<ContextoIdioma>(() => {
    const textos = idioma === "pt" ? pt : en;
    const indice = idioma === "pt" ? 0 : 1;
    return {
      idioma,
      trocar,
      t: (chave, vars) =>
        textos[chave].replace(/\{(\w+)\}/g, (_, nome: string) => String(vars?.[nome] ?? `{${nome}}`)),
      rotulo: (grupo, valor) => {
        const par = (ROTULOS[grupo] as Record<string, readonly [string, string]>)[valor];
        return par ? par[indice] : valor;
      },
    };
  }, [idioma, trocar]);

  return <Contexto.Provider value={valor}>{children}</Contexto.Provider>;
}

export function useIdioma(): ContextoIdioma {
  const contexto = useContext(Contexto);
  if (!contexto) throw new Error("useIdioma fora do ProvedorIdioma");
  return contexto;
}
