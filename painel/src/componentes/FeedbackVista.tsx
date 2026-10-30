import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ErroApi, ErroRede } from "../api";
import { useIdioma } from "../i18n";
import type { Correcao, FeedbackItem, UsoFeedback } from "../tipos";
import { dataHora } from "../util";

type Filtro = "todos" | UsoFeedback;

export function FeedbackVista({ token, aoNaoAutorizado }: { token: string; aoNaoAutorizado: () => void }) {
  const { t, rotulo, idioma } = useIdioma();
  const [itens, setItens] = useState<FeedbackItem[] | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [filtro, setFiltro] = useState<Filtro>("todos");
  const [ocupado, setOcupado] = useState<string | null>(null);

  const mensagem = useCallback(
    (falha: unknown) => {
      if (falha instanceof ErroApi) {
        if (falha.status === 401) aoNaoAutorizado();
        return falha.detalhe ?? t("erroGenerico", { status: falha.status });
      }
      return falha instanceof ErroRede ? t("erroRede") : t("erroGenerico", { status: "?" });
    },
    [aoNaoAutorizado, t],
  );

  useEffect(() => {
    api
      .listarFeedback(token)
      .then(setItens)
      .catch((falha) => {
        setErro(mensagem(falha));
        setItens([]);
      });
  }, [token, mensagem]);

  async function alternar(item: FeedbackItem) {
    setOcupado(item.id);
    try {
      const atualizado = await api.alterarUso(token, item.id, item.uso === "exemplo" ? "quarentena" : "exemplo");
      setItens((lista) => lista?.map((i) => (i.id === item.id ? atualizado : i)) ?? lista);
    } catch (falha) {
      setErro(mensagem(falha));
    } finally {
      setOcupado(null);
    }
  }

  const contagem = useMemo(
    () => ({
      todos: itens?.length ?? 0,
      exemplo: itens?.filter((i) => i.uso === "exemplo").length ?? 0,
      quarentena: itens?.filter((i) => i.uso === "quarentena").length ?? 0,
    }),
    [itens],
  );
  const visiveis = (itens ?? []).filter((i) => filtro === "todos" || i.uso === filtro);

  // Os três campos da decisão; na linha do analista, o que ele mudou fica em destaque.
  const campos = (decisao: Correcao, comparar: Correcao | null) =>
    (
      [
        ["classificacao", "classificacao"],
        ["severidade", "severidade"],
        ["acao_sugerida", "acao"],
      ] as const
    ).map(([campo, grupo]) => (
      <span key={campo} className={comparar && comparar[campo] !== decisao[campo] ? "mudou" : undefined}>
        {rotulo(grupo, decisao[campo])}
      </span>
    ));

  const filtros: { valor: Filtro; nome: string }[] = [
    { valor: "todos", nome: t("todos") },
    { valor: "quarentena", nome: t("quarentena") },
    { valor: "exemplo", nome: t("exemplos") },
  ];

  return (
    <main className="feedback">
      <div className="feedback__cabeca">
        <div>
          <h1>{t("feedback")}</h1>
          <p className="feedback__texto">{t("feedbackTexto")}</p>
        </div>
        <div className="filtros" role="group" aria-label={t("feedback")}>
          {filtros.map(({ valor, nome }) => (
            <button key={valor} type="button" aria-pressed={filtro === valor} onClick={() => setFiltro(valor)}>
              {nome}
              <span className="mono">{contagem[valor]}</span>
            </button>
          ))}
        </div>
      </div>

      {erro && (
        <p className="campo__erro" role="alert">
          {erro}
        </p>
      )}

      {itens === null ? (
        <ol className="registros" aria-busy="true">
          {[0, 1, 2].map((i) => (
            <li key={i} className="registro registro--esqueleto" />
          ))}
        </ol>
      ) : visiveis.length === 0 ? (
        <p className="feedback__vazio">{itens.length === 0 ? t("feedbackVazio") : t("filtroVazio")}</p>
      ) : (
        <ol className="registros">
          {visiveis.map((item) => (
            <li key={item.id} className={`registro${item.uso === "quarentena" ? " registro--quarentena" : ""}`}>
              <span className={`registro__importancia registro__importancia--${item.importancia}`}>
                <strong>{rotulo("importancia", item.importancia)}</strong>
                <span>{t("importancia")}</span>
              </span>
              <div className="registro__corpo">
                <p className="registro__titulo">
                  <span className="mono">{t("regra", { id: item.regra.id })}</span>
                  {item.regra.descricao}
                </p>
                <dl className="registro__decisao">
                  <div>
                    <dt>{t("iaDisse")}</dt>
                    <dd>{campos(item.sugestao, null)}</dd>
                  </div>
                  <div>
                    <dt>{t("analista")}</dt>
                    <dd>{campos(item.final, item.sugestao)}</dd>
                  </div>
                </dl>
                {item.nota && <p className="registro__nota">{item.nota}</p>}
                <p className="registro__motivo">{item.motivo_importancia}</p>
              </div>
              <div className="registro__uso">
                <span className={`selo selo--${item.uso}`}>{rotulo("uso", item.uso)}</span>
                <p className="registro__motivo">{item.motivo_uso}</p>
                <button type="button" className="botao" onClick={() => alternar(item)} disabled={ocupado === item.id}>
                  {item.uso === "quarentena" ? t("liberar") : t("quarentenar")}
                </button>
                <span className="registro__data mono">{dataHora(item.criado_em, idioma)} UTC</span>
              </div>
            </li>
          ))}
        </ol>
      )}
    </main>
  );
}
