import { describe, expect, it } from "vitest";
import { agruparPorIncidente, estaPendente, type Alerta, type ResumoAnalise } from "./tipos";

const resumo = (revisao: ResumoAnalise["revisao"]): ResumoAnalise => ({
  id: 1,
  revisao,
  classificacao: "verdadeiro_positivo",
  severidade: "alta",
  acao_sugerida: "bloquear_ip",
  indicios_manipulacao: false,
});

function alerta(id: number, incidente: number | null, extra: Partial<Alerta> = {}): Alerta {
  return {
    id,
    wazuh_id: `${id}`,
    rule_id: "5710",
    rule_level: 5,
    rule_description: "sshd: Attempt to login using a non-existent user",
    agent_name: "srv-lab-01",
    srcip: "203.0.113.45",
    full_log: null,
    recebido_em: "2026-10-30T14:00:00",
    analise: null,
    incidente:
      incidente === null
        ? null
        : { id: incidente, total: 3, nivel_max: 10, primeiro_em: "2026-10-30T13:50:00", ultimo_em: "2026-10-30T14:00:00", decisao: null },
    ...extra,
  };
}

describe("agruparPorIncidente", () => {
  it("deixa uma faixa por incidente, na posição do alerta mais novo", () => {
    const lista = [alerta(3, 7), alerta(2, null), alerta(1, 7)];
    expect(agruparPorIncidente(lista).map((a) => a.id)).toEqual([3, 2]);
  });

  it("prefere o alerta que já tem análise como representante", () => {
    const lista = [alerta(3, 7), alerta(2, 7, { analise: resumo("pendente") }), alerta(1, 7)];
    expect(agruparPorIncidente(lista).map((a) => a.id)).toEqual([2]);
  });
});

describe("estaPendente", () => {
  it("sai da fila quando o incidente foi decidido, mesmo sem análise própria", () => {
    const decidido = alerta(1, 7);
    decidido.incidente!.decisao = "descartada";
    expect(estaPendente(decidido)).toBe(false);
  });

  it("continua na fila com análise pendente", () => {
    expect(estaPendente(alerta(1, 7, { analise: resumo("pendente") }))).toBe(true);
    expect(estaPendente(alerta(1, null, { analise: resumo("aprovada") }))).toBe(false);
  });
});
