import type { Idioma } from "./i18n";

export type Banda = "baixo" | "medio" | "alto" | "critico";

/** Escala fixa de magnitude do nível da regra (0 a 15), a mesma em todas as telas. */
export function banda(nivel: number): Banda {
  if (nivel >= 12) return "critico";
  if (nivel >= 8) return "alto";
  if (nivel >= 5) return "medio";
  return "baixo";
}

/** O SQLite devolve datas sem fuso; a API grava sempre em UTC. */
export function comoData(iso: string): Date {
  return new Date(/(z|[+-]\d\d:?\d\d)$/i.test(iso) ? iso : `${iso}Z`);
}

const localidade = (idioma: Idioma) => (idioma === "pt" ? "pt-BR" : "en-US");

export function hora(iso: string, idioma: Idioma): string {
  return new Intl.DateTimeFormat(localidade(idioma), {
    timeZone: "UTC",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).format(comoData(iso));
}

export function dataHora(iso: string, idioma: Idioma): string {
  const data = new Intl.DateTimeFormat(localidade(idioma), {
    timeZone: "UTC",
    day: "2-digit",
    month: "2-digit",
  }).format(comoData(iso));
  return `${data} ${hora(iso, idioma)}`;
}

/** Atalhos de teclado não disparam enquanto o analista digita. */
export function digitando(evento: KeyboardEvent): boolean {
  const alvo = evento.target as HTMLElement | null;
  if (!alvo) return false;
  return alvo.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(alvo.tagName);
}

export function combina(busca: string, ...campos: (string | null)[]): boolean {
  const termo = busca.trim().toLowerCase();
  if (!termo) return true;
  return campos.some((campo) => campo?.toLowerCase().includes(termo));
}
