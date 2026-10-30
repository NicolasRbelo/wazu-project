// O armazenamento do navegador pode falhar (aba privada, site bloqueado): o painel segue sem ele.

type Area = "sessao" | "local";

function area(qual: Area): Storage {
  return qual === "sessao" ? sessionStorage : localStorage;
}

export function ler(qual: Area, chave: string): string | null {
  try {
    return area(qual).getItem(chave);
  } catch {
    return null;
  }
}

export function gravar(qual: Area, chave: string, valor: string | null): void {
  try {
    if (valor === null) area(qual).removeItem(chave);
    else area(qual).setItem(chave, valor);
  } catch {
    // sem armazenamento: o valor vale só enquanto a página está aberta
  }
}

// Token só na sessão da aba: some ao fechar, nunca vai para o localStorage.
export const CHAVE_TOKEN = "wazuh-triagem:token";
export const CHAVE_IDIOMA = "wazuh-triagem:idioma";
