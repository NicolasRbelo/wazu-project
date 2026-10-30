import { ArrowLeft, ShieldWarning } from "@phosphor-icons/react";
import { useCallback, useEffect, useState } from "react";
import { api, ErroApi, ErroRede } from "../api";
import { useIdioma } from "../i18n";
import { resumoDe, type Alerta, type Analise, type PedidoRevisao, type Reputacao, type ResumoAnalise } from "../tipos";
import { dataHora, digitando } from "../util";
import { AnaliseBloco } from "./AnaliseBloco";
import { BarraDecisao, type Formulario } from "./BarraDecisao";
import { Carimbo, Designador } from "./Marcas";
import { ReputacaoBloco, type EstadoReputacao } from "./ReputacaoBloco";

interface Props {
  alerta: Alerta;
  token: string;
  aoResumo: (alertaId: number, resumo: ResumoAnalise) => void;
  aoDecidido: (alertaId: number, resumo: ResumoAnalise) => void;
  aoProximo: () => void;
  aoAnterior: () => void;
  aoVoltar: () => void;
  aoNaoAutorizado: () => void;
}

export function Detalhe({ alerta, token, aoResumo, aoDecidido, aoProximo, aoAnterior, aoVoltar, aoNaoAutorizado }: Props) {
  const { t, idioma } = useIdioma();
  // undefined: carregando; null: o alerta ainda não tem análise.
  const [analise, setAnalise] = useState<Analise | null | undefined>(alerta.analise ? undefined : null);
  const [analisando, setAnalisando] = useState(false);
  const [erroAnalise, setErroAnalise] = useState<string | null>(null);
  const [reputacao, setReputacao] = useState<Reputacao | null>(null);
  const [estadoReputacao, setEstadoReputacao] = useState<EstadoReputacao>("ocioso");
  const [erroReputacao, setErroReputacao] = useState<string | null>(null);
  const [formulario, setFormulario] = useState<Formulario>(null);

  const mensagem = useCallback(
    (falha: unknown): string => {
      if (falha instanceof ErroApi) {
        if (falha.status === 401) aoNaoAutorizado();
        return falha.detalhe ?? t("erroGenerico", { status: falha.status });
      }
      if (falha instanceof ErroRede) return t("erroRede");
      return t("erroGenerico", { status: "?" });
    },
    [aoNaoAutorizado, t],
  );

  const consultarReputacao = useCallback(async () => {
    setEstadoReputacao("carregando");
    try {
      setReputacao(await api.reputacao(token, alerta.id));
      setEstadoReputacao("ocioso");
    } catch (falha) {
      setErroReputacao(mensagem(falha));
      setEstadoReputacao("erro");
    }
  }, [token, alerta.id, mensagem]);

  // O componente é recriado a cada alerta (key no Painel): isto roda uma vez por alerta aberto.
  useEffect(() => {
    if (!alerta.analise) return;
    let vivo = true;
    api
      .analise(token, alerta.id)
      .then((encontrada) => vivo && setAnalise(encontrada))
      .catch((falha) => {
        if (!vivo) return;
        setAnalise(null);
        setErroAnalise(mensagem(falha));
      });
    // Com análise feita, a reputação já está no cache do backend: buscar não gasta cota.
    void consultarReputacao();
    return () => {
      vivo = false;
    };
  }, []); // de propósito: só ao abrir o alerta

  const analisar = useCallback(
    async (refazer: boolean) => {
      setAnalisando(true);
      setErroAnalise(null);
      try {
        const nova = await api.analisar(token, alerta.id, refazer);
        setAnalise(nova);
        aoResumo(alerta.id, resumoDe(nova));
        if (!reputacao) void consultarReputacao();
      } catch (falha) {
        setErroAnalise(mensagem(falha));
      } finally {
        setAnalisando(false);
      }
    },
    [token, alerta.id, aoResumo, reputacao, consultarReputacao, mensagem],
  );

  const decidir = useCallback(
    async (pedido: PedidoRevisao): Promise<string | null> => {
      try {
        const revisada = await api.revisar(token, alerta.id, pedido);
        setAnalise(revisada);
        setFormulario(null);
        aoDecidido(alerta.id, resumoDe(revisada));
        return null;
      } catch (falha) {
        return mensagem(falha);
      }
    },
    [token, alerta.id, aoDecidido, mensagem],
  );

  const [aprovando, setAprovando] = useState(false);
  const [erroDecisao, setErroDecisao] = useState<string | null>(null);

  const aprovar = useCallback(async () => {
    setAprovando(true);
    setErroDecisao(await decidir({ decisao: "aprovada" }));
    setAprovando(false);
  }, [decidir]);

  const pendente = analise?.revisao === "pendente";

  useEffect(() => {
    const aoTeclar = (evento: KeyboardEvent) => {
      if (digitando(evento) || evento.ctrlKey || evento.metaKey || evento.altKey) return;
      const tecla = evento.key.toLowerCase();
      if (tecla === "escape") setFormulario(null);
      else if (tecla === "i" && analise === null && !analisando) {
        evento.preventDefault();
        void analisar(false);
      } else if (pendente && formulario === null && !aprovando && tecla === "a") {
        evento.preventDefault();
        void aprovar();
      } else if (pendente && tecla === "c") {
        evento.preventDefault();
        setFormulario("corrigir");
      } else if (pendente && tecla === "d") {
        evento.preventDefault();
        setFormulario("descartar");
      }
    };
    window.addEventListener("keydown", aoTeclar);
    return () => window.removeEventListener("keydown", aoTeclar);
  }, [analise, analisando, pendente, formulario, aprovando, analisar, aprovar]);

  const decidida = analise && analise.revisao !== "pendente" ? analise.revisao : null;

  return (
    <section className="detalhe" aria-labelledby="detalhe-titulo">
      <div className="detalhe__rolagem">
        <button type="button" className="botao botao--fantasma detalhe__voltar" onClick={aoVoltar}>
          <ArrowLeft size={16} weight="bold" aria-hidden="true" />
          {t("voltar")}
        </button>

        <header className="detalhe__cabeca">
          <Designador nivel={alerta.rule_level} grande />
          <div className="detalhe__titulos">
            <h1 id="detalhe-titulo">{alerta.rule_description}</h1>
            <ul className="detalhe__meta mono">
              <li>{t("regra", { id: alerta.rule_id })}</li>
              {alerta.agent_name && <li>{t("agente", { nome: alerta.agent_name })}</li>}
              {alerta.srcip && <li>{alerta.srcip}</li>}
              <li>{t("recebido", { quando: dataHora(alerta.recebido_em, idioma) })}</li>
            </ul>
          </div>
          {decidida && <Carimbo revisao={decidida} grande bater />}
        </header>

        <div className="detalhe__grade">
          <section className="bloco evidencia" aria-labelledby="evidencia-titulo">
            <h2 id="evidencia-titulo">{t("evidencia")}</h2>
            <p className="evidencia__aviso">
              <ShieldWarning size={16} weight="bold" aria-hidden="true" />
              {t("naoConfiavel")}
            </p>
            {/* Texto do atacante: React escapa tudo, nada aqui vira HTML. */}
            {alerta.full_log ? (
              <pre className="evidencia__log">{alerta.full_log}</pre>
            ) : (
              <p className="bloco__vazio">{t("semLog")}</p>
            )}
          </section>

          <ReputacaoBloco
            alerta={alerta}
            reputacao={reputacao}
            estado={estadoReputacao}
            erro={erroReputacao}
            aoConsultar={consultarReputacao}
          />

          <AnaliseBloco analise={analise} analisando={analisando} erro={erroAnalise} />
        </div>
      </div>

      <BarraDecisao
        analise={analise}
        analisando={analisando}
        formulario={formulario}
        aoFormulario={setFormulario}
        aprovando={aprovando}
        erro={erroDecisao}
        aoAprovar={aprovar}
        aoDecidir={decidir}
        aoAnalisar={analisar}
        aoProximo={aoProximo}
        aoAnterior={aoAnterior}
      />
    </section>
  );
}
