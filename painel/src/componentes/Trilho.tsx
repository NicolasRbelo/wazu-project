import { ShieldWarning } from "@phosphor-icons/react";
import { LayoutGroup, motion } from "motion/react";
import { useEffect, useRef, type ReactNode } from "react";
import { useIdioma } from "../i18n";
import type { Alerta } from "../tipos";
import { hora } from "../util";
import { Carimbo, Designador } from "./Marcas";

interface Props {
  pendentes: Alerta[];
  decididos: Alerta[];
  carregando: boolean;
  filtrando: boolean;
  selecionado: number | null;
  recemDecidido: number | null;
  aoSelecionar: (id: number) => void;
}

export function Trilho({ pendentes, decididos, carregando, filtrando, selecionado, recemDecidido, aoSelecionar }: Props) {
  const { t } = useIdioma();
  const comuns = { carregando, selecionado, recemDecidido, aoSelecionar };
  return (
    <section className="trilho" aria-label={t("fila")}>
      {/* Mesmo layoutId nas duas baias: a faixa decidida desliza de uma para a outra. */}
      <LayoutGroup>
        <Baia
          titulo={t("pendentes")}
          alertas={pendentes}
          vazio={
            filtrando ? (
              t("semResultados")
            ) : (
              <>
                {t("filaVazia")}
                <span className="baia__dica mono">{t("filaVaziaDica")}</span>
              </>
            )
          }
          {...comuns}
        />
        <Baia
          titulo={t("decididos")}
          alertas={decididos}
          vazio={filtrando ? t("semResultados") : t("nadaDecidido")}
          {...comuns}
        />
      </LayoutGroup>
    </section>
  );
}

interface PropsBaia extends Omit<Props, "pendentes" | "decididos" | "filtrando"> {
  titulo: string;
  alertas: Alerta[];
  vazio: ReactNode;
}

function Baia({ titulo, alertas, vazio, carregando, selecionado, recemDecidido, aoSelecionar }: PropsBaia) {
  const { t } = useIdioma();
  return (
    <div className="baia">
      <div className="baia__cabeca">
        <h2>{titulo}</h2>
        {!carregando && <span className="mono">{t("faixas", { n: alertas.length })}</span>}
      </div>
      {carregando ? (
        <ol className="baia__faixas" aria-busy="true">
          {[0, 1, 2, 3].map((i) => (
            <li key={i}>
              <div className="faixa faixa--esqueleto" />
            </li>
          ))}
        </ol>
      ) : alertas.length === 0 ? (
        <p className="baia__vazio">{vazio}</p>
      ) : (
        <ol className="baia__faixas">
          {alertas.map((alerta) => (
            <motion.li
              key={alerta.id}
              layout="position"
              layoutId={`faixa-${alerta.id}`}
              transition={{ type: "spring", stiffness: 340, damping: 34 }}
            >
              <Faixa
                alerta={alerta}
                selecionada={alerta.id === selecionado}
                recuada={selecionado !== null && alerta.id !== selecionado}
                bater={alerta.id === recemDecidido}
                aoSelecionar={aoSelecionar}
              />
            </motion.li>
          ))}
        </ol>
      )}
    </div>
  );
}

interface PropsFaixa {
  alerta: Alerta;
  selecionada: boolean;
  recuada: boolean;
  bater: boolean;
  aoSelecionar: (id: number) => void;
}

function Faixa({ alerta, selecionada, recuada, bater, aoSelecionar }: PropsFaixa) {
  const { t, rotulo, idioma } = useIdioma();
  const ref = useRef<HTMLButtonElement>(null);
  const resumo = alerta.analise;
  const decidida = resumo !== null && resumo.revisao !== "pendente";

  // Navegar com J/K mantém a faixa aberta à vista e leva o foco junto, se ele estava no trilho.
  useEffect(() => {
    if (!selecionada || !ref.current) return;
    ref.current.scrollIntoView({ block: "nearest" });
    const ativo = document.activeElement;
    if (ativo === document.body || ativo?.classList.contains("faixa")) ref.current.focus({ preventScroll: true });
  }, [selecionada]);

  let estado: ReactNode;
  if (resumo === null) estado = <span className="faixa__ia faixa__ia--nada">{t("semAnalise")}</span>;
  else if (resumo.revisao !== "pendente") estado = <Carimbo revisao={resumo.revisao} bater={bater} />;
  else if (resumo.indicios_manipulacao)
    estado = (
      <span className="faixa__ia faixa__ia--perigo">
        <ShieldWarning size={14} weight="bold" aria-hidden="true" />
        {t("manipulacao")}
      </span>
    );
  else
    estado = (
      <span className="faixa__ia">
        {rotulo("severidade", resumo.severidade)}, {rotulo("acao", resumo.acao_sugerida)}
      </span>
    );

  const classes = ["faixa", decidida && "faixa--decidida", recuada && "faixa--recuada"].filter(Boolean).join(" ");

  return (
    <button
      ref={ref}
      type="button"
      className={classes}
      aria-current={selecionada ? "true" : undefined}
      onClick={() => aoSelecionar(alerta.id)}
    >
      <Designador nivel={alerta.rule_level} />
      <span className="faixa__campo faixa__regra">
        <span className="faixa__chave">
          {alerta.rule_id}
          {alerta.agent_name && <span className="faixa__agente">{alerta.agent_name}</span>}
          {/* Em telas estreitas a coluna de origem some e o IP sobe para esta linha. */}
          {alerta.srcip && <span className="faixa__ip mono">{alerta.srcip}</span>}
        </span>
        <span className="faixa__valor">{alerta.rule_description}</span>
      </span>
      <span className="faixa__campo faixa__origem">
        <span className="faixa__chave">{t("origem")}</span>
        <span className="faixa__valor mono">{alerta.srcip ?? "-"}</span>
      </span>
      <span className="faixa__campo faixa__estado">
        <span className="faixa__chave mono">{hora(alerta.recebido_em, idioma)} UTC</span>
        <span className="faixa__valor">{estado}</span>
      </span>
    </button>
  );
}
