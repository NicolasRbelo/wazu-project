import { MagnifyingGlass, Plugs, PlugsConnected, SignOut } from "@phosphor-icons/react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ErroApi } from "../api";
import { useIdioma } from "../i18n";
import { estaPendente, type Alerta, type ResumoAnalise } from "../tipos";
import { combina, digitando } from "../util";
import { Detalhe } from "./Detalhe";
import { FeedbackVista } from "./FeedbackVista";
import { TrocaIdioma } from "./TrocaIdioma";
import { Trilho } from "./Trilho";

const INTERVALO_ATUALIZACAO = 10_000;
const telaEstreita = () => window.matchMedia("(max-width: 860px)").matches;

type Vista = "fila" | "feedback";

export function Painel({ token, aoSair }: { token: string; aoSair: (porRecusa: boolean) => void }) {
  const { t } = useIdioma();
  const [vista, setVista] = useState<Vista>("fila");
  const [alertas, setAlertas] = useState<Alerta[] | null>(null);
  const [online, setOnline] = useState(true);
  const [selecionado, setSelecionado] = useState<number | null>(null);
  const [recemDecidido, setRecemDecidido] = useState<number | null>(null);
  const [busca, setBusca] = useState("");

  const naoAutorizado = useCallback(() => aoSair(true), [aoSair]);

  const carregar = useCallback(async () => {
    try {
      setAlertas(await api.listarAlertas(token));
      setOnline(true);
    } catch (erro) {
      if (erro instanceof ErroApi && erro.status === 401) naoAutorizado();
      else setOnline(false);
    }
  }, [token, naoAutorizado]);

  // Alertas novos do Wazuh aparecem sozinhos; a busca para quando a aba não está visível.
  useEffect(() => {
    void carregar();
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") void carregar();
    }, INTERVALO_ATUALIZACAO);
    return () => window.clearInterval(id);
  }, [carregar]);

  const filtrados = useMemo(
    () => (alertas ?? []).filter((a) => combina(busca, a.srcip, a.rule_id, a.agent_name, a.rule_description)),
    [alertas, busca],
  );
  const pendentes = useMemo(() => filtrados.filter(estaPendente), [filtrados]);
  const decididos = useMemo(() => filtrados.filter((a) => !estaPendente(a)), [filtrados]);
  const ordem = useMemo(() => [...pendentes, ...decididos], [pendentes, decididos]);
  const totalPendentes = useMemo(() => (alertas ?? []).filter(estaPendente).length, [alertas]);

  // Na tela larga, a fila já abre na primeira faixa pendente.
  useEffect(() => {
    if (selecionado !== null || !alertas || telaEstreita()) return;
    const primeiro = alertas.find(estaPendente);
    if (primeiro) setSelecionado(primeiro.id);
  }, [alertas, selecionado]);

  const mover = useCallback(
    (passo: 1 | -1) => {
      if (ordem.length === 0) return;
      const atual = ordem.findIndex((a) => a.id === selecionado);
      const destino = atual === -1 ? 0 : Math.min(ordem.length - 1, Math.max(0, atual + passo));
      setSelecionado(ordem[destino].id);
    },
    [ordem, selecionado],
  );

  useEffect(() => {
    if (vista !== "fila") return;
    const aoTeclar = (evento: KeyboardEvent) => {
      if (digitando(evento) || evento.ctrlKey || evento.metaKey || evento.altKey) return;
      const tecla = evento.key.toLowerCase();
      if (tecla === "j") {
        evento.preventDefault();
        mover(1);
      } else if (tecla === "k") {
        evento.preventDefault();
        mover(-1);
      }
    };
    window.addEventListener("keydown", aoTeclar);
    return () => window.removeEventListener("keydown", aoTeclar);
  }, [vista, mover]);

  const atualizarResumo = useCallback((alertaId: number, resumo: ResumoAnalise) => {
    setAlertas((lista) => lista?.map((a) => (a.id === alertaId ? { ...a, analise: resumo } : a)) ?? lista);
  }, []);

  // Decidir manda a faixa para Decididos e já abre a próxima pendente.
  const aoDecidido = useCallback(
    (alertaId: number, resumo: ResumoAnalise) => {
      const indice = pendentes.findIndex((a) => a.id === alertaId);
      const restantes = pendentes.filter((a) => a.id !== alertaId);
      setRecemDecidido(alertaId);
      atualizarResumo(alertaId, resumo);
      const proxima = restantes[Math.min(Math.max(indice, 0), restantes.length - 1)];
      if (proxima && !telaEstreita()) setSelecionado(proxima.id);
    },
    [pendentes, atualizarResumo],
  );

  const alertaAberto = alertas?.find((a) => a.id === selecionado) ?? null;

  return (
    <div className={`painel${alertaAberto ? " painel--com-alerta" : ""}`}>
      <header className="barra">
        <span className="barra__marca">wazuh-triagem</span>
        <nav className="abas" aria-label={t("navegacao")}>
          <button type="button" aria-current={vista === "fila" ? "page" : undefined} onClick={() => setVista("fila")}>
            {t("fila")}
            <span className="abas__contagem mono">{totalPendentes}</span>
          </button>
          <button
            type="button"
            aria-current={vista === "feedback" ? "page" : undefined}
            onClick={() => setVista("feedback")}
          >
            {t("feedback")}
          </button>
        </nav>
        {vista === "fila" && (
          <label className="busca">
            <MagnifyingGlass size={16} weight="bold" aria-hidden="true" />
            <input
              type="search"
              value={busca}
              onChange={(e) => setBusca(e.target.value)}
              placeholder={t("buscarDica")}
              aria-label={t("buscar")}
              spellCheck={false}
            />
          </label>
        )}
        <div className="barra__direita">
          <span
            className={`estado-api${online ? "" : " estado-api--fora"}`}
            role="status"
            title={online ? t("apiConectada") : t("apiFora")}
          >
            {online ? (
              <PlugsConnected size={16} weight="bold" aria-hidden="true" />
            ) : (
              <Plugs size={16} weight="bold" aria-hidden="true" />
            )}
            <span className="barra__rotulo-largo">{online ? t("apiConectada") : t("apiFora")}</span>
          </span>
          <TrocaIdioma />
          <button
            type="button"
            className="botao botao--fantasma barra__sair"
            onClick={() => aoSair(false)}
            aria-label={t("sair")}
          >
            <SignOut size={16} weight="bold" aria-hidden="true" />
            <span className="barra__rotulo-largo">{t("sair")}</span>
          </button>
        </div>
      </header>

      {vista === "fila" ? (
        <main className="fila">
          <Trilho
            pendentes={pendentes}
            decididos={decididos}
            carregando={alertas === null}
            filtrando={busca.trim() !== ""}
            selecionado={selecionado}
            recemDecidido={recemDecidido}
            aoSelecionar={setSelecionado}
          />
          {alertaAberto ? (
            <Detalhe
              key={alertaAberto.id}
              alerta={alertaAberto}
              token={token}
              aoResumo={atualizarResumo}
              aoDecidido={aoDecidido}
              aoProximo={() => mover(1)}
              aoAnterior={() => mover(-1)}
              aoVoltar={() => setSelecionado(null)}
              aoNaoAutorizado={naoAutorizado}
            />
          ) : (
            <section className="detalhe detalhe--vazio">
              <p>{t("selecione")}</p>
            </section>
          )}
        </main>
      ) : (
        <FeedbackVista token={token} aoNaoAutorizado={naoAutorizado} />
      )}
    </div>
  );
}
