import { ArrowClockwise, CaretUp, Check, PencilSimple, Sparkle, Trash } from "@phosphor-icons/react";
import { useState, type FormEvent } from "react";
import { useIdioma } from "../i18n";
import { ACOES, CLASSIFICACOES, SEVERIDADES, type Analise, type Correcao, type PedidoRevisao } from "../tipos";
import { dataHora } from "../util";
import { Carimbo } from "./Marcas";

export type Formulario = "corrigir" | "descartar" | null;

// O mesmo mínimo de app/schemas.py (MINIMO_NOTA).
const MINIMO_NOTA = 10;

interface Props {
  analise: Analise | null | undefined;
  analisando: boolean;
  formulario: Formulario;
  aoFormulario: (formulario: Formulario) => void;
  aprovando: boolean;
  erro: string | null;
  aoAprovar: () => void;
  aoDecidir: (pedido: PedidoRevisao) => Promise<string | null>;
  aoAnalisar: (refazer: boolean) => void;
  aoProximo: () => void;
  aoAnterior: () => void;
}

export function BarraDecisao({
  analise,
  analisando,
  formulario,
  aoFormulario,
  aprovando,
  erro,
  aoAprovar,
  aoDecidir,
  aoAnalisar,
  aoProximo,
  aoAnterior,
}: Props) {
  const { t, idioma } = useIdioma();
  const pendente = analise?.revisao === "pendente";

  const alternar = (qual: Exclude<Formulario, null>) => aoFormulario(formulario === qual ? null : qual);

  let acoes;
  if (analise === null) {
    acoes = (
      <>
        <button type="button" className="botao botao--primario" onClick={() => aoAnalisar(false)} disabled={analisando}>
          <Sparkle size={16} weight="bold" aria-hidden="true" />
          {analisando ? t("analisando") : t("analisar")}
          <kbd>I</kbd>
        </button>
        <span className="decisao__dica">{t("decidirDica")}</span>
      </>
    );
  } else if (analise && analise.revisao !== "pendente") {
    acoes = (
      <>
        <span className="decisao__feito">
          <Carimbo revisao={analise.revisao} />
          {analise.revisado_em && (
            <span className="mono">{t("decididoEm", { quando: dataHora(analise.revisado_em, idioma) })}</span>
          )}
        </span>
        <button type="button" className="botao" onClick={() => aoAnalisar(true)} disabled={analisando}>
          <ArrowClockwise size={16} weight="bold" aria-hidden="true" />
          {analisando ? t("analisando") : t("refazer")}
        </button>
      </>
    );
  } else {
    acoes = (
      <>
        <button
          type="button"
          className="botao botao--primario"
          onClick={aoAprovar}
          disabled={!pendente || aprovando || formulario !== null}
          title={t("comTecla", { acao: t("aprovar"), tecla: "A" })}
        >
          <Check size={16} weight="bold" aria-hidden="true" />
          {t("aprovar")}
          <kbd>A</kbd>
        </button>
        <button
          type="button"
          className="botao"
          aria-expanded={formulario === "corrigir"}
          disabled={!pendente}
          onClick={() => alternar("corrigir")}
          title={t("comTecla", { acao: t("corrigir"), tecla: "C" })}
        >
          <PencilSimple size={16} weight="bold" aria-hidden="true" />
          {t("corrigir")}
          <kbd>C</kbd>
        </button>
        <button
          type="button"
          className="botao"
          aria-expanded={formulario === "descartar"}
          disabled={!pendente}
          onClick={() => alternar("descartar")}
          title={t("comTecla", { acao: t("descartar"), tecla: "D" })}
        >
          <Trash size={16} weight="bold" aria-hidden="true" />
          {t("descartar")}
          <kbd>D</kbd>
        </button>
      </>
    );
  }

  return (
    <div className="decisao">
      {formulario && analise && pendente && (
        <FormularioDecisao
          key={formulario}
          tipo={formulario}
          analise={analise}
          aoCancelar={() => aoFormulario(null)}
          aoEnviar={aoDecidir}
        />
      )}
      {erro && (
        <p className="campo__erro decisao__erro" role="alert">
          {erro}
        </p>
      )}
      <div className="decisao__barra">
        <div className={`decisao__acoes${pendente ? " decisao__acoes--tres" : ""}`}>{acoes}</div>
        <div className="decisao__navegar">
          <button
            type="button"
            className="botao botao--fantasma decisao__anterior"
            onClick={aoAnterior}
            aria-label={t("anterior")}
            title={t("comTecla", { acao: t("anterior"), tecla: "K" })}
          >
            <CaretUp size={16} weight="bold" aria-hidden="true" />
            <kbd>K</kbd>
          </button>
          <button
            type="button"
            className="botao"
            onClick={aoProximo}
            title={t("comTecla", { acao: t("proximo"), tecla: "J" })}
          >
            {t("proximo")}
            <kbd>J</kbd>
          </button>
        </div>
      </div>
    </div>
  );
}

interface PropsFormulario {
  tipo: Exclude<Formulario, null>;
  analise: Analise;
  aoCancelar: () => void;
  aoEnviar: (pedido: PedidoRevisao) => Promise<string | null>;
}

function FormularioDecisao({ tipo, analise, aoCancelar, aoEnviar }: PropsFormulario) {
  const { t, rotulo } = useIdioma();
  const base: Correcao = {
    classificacao: analise.sugestao.classificacao,
    severidade: analise.sugestao.severidade,
    acao_sugerida: analise.sugestao.acao_sugerida,
  };
  const [correcao, setCorrecao] = useState<Correcao>(base);
  const [nota, setNota] = useState("");
  const [erro, setErro] = useState<string | null>(null);
  const [enviando, setEnviando] = useState(false);

  async function enviar(evento: FormEvent) {
    evento.preventDefault();
    if (nota.trim().length < MINIMO_NOTA) {
      setErro(t("notaCurta", { n: MINIMO_NOTA }));
      return;
    }
    const igual =
      correcao.classificacao === base.classificacao &&
      correcao.severidade === base.severidade &&
      correcao.acao_sugerida === base.acao_sugerida;
    if (tipo === "corrigir" && igual) {
      setErro(t("correcaoIgual"));
      return;
    }
    setEnviando(true);
    const falha = await aoEnviar(
      tipo === "corrigir" ? { decisao: "corrigida", correcao, nota: nota.trim() } : { decisao: "descartada", nota: nota.trim() },
    );
    if (falha) {
      setErro(falha);
      setEnviando(false);
    }
  }

  const seletor = <K extends keyof Correcao>(campo: K, rotuloCampo: string, grupo: "classificacao" | "severidade" | "acao", opcoes: Correcao[K][], foco = false) => (
    <label className="campo">
      <span className="campo__rotulo">{rotuloCampo}</span>
      <select
        value={correcao[campo]}
        autoFocus={foco}
        onChange={(e) => setCorrecao((atual) => ({ ...atual, [campo]: e.target.value as Correcao[K] }))}
      >
        {opcoes.map((opcao) => (
          <option key={opcao} value={opcao}>
            {rotulo(grupo, opcao)}
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <form
      className={`decisao__formulario decisao__formulario--${tipo}`}
      onSubmit={enviar}
      onKeyDown={(e) => e.key === "Escape" && aoCancelar()}
    >
      {tipo === "corrigir" && (
        <div className="decisao__campos">
          {seletor("classificacao", t("classificacao"), "classificacao", CLASSIFICACOES, true)}
          {seletor("severidade", t("severidade"), "severidade", SEVERIDADES)}
          {seletor("acao_sugerida", t("acao"), "acao", ACOES)}
        </div>
      )}
      <label className="campo campo--nota">
        <span className="campo__rotulo">{t("nota")}</span>
        <textarea
          rows={3}
          maxLength={1000}
          value={nota}
          autoFocus={tipo === "descartar"}
          onChange={(e) => setNota(e.target.value)}
          aria-describedby={`nota-ajuda-${tipo}`}
          aria-invalid={erro ? true : undefined}
        />
        <span id={`nota-ajuda-${tipo}`} className="campo__ajuda">
          {t("notaAjuda", { n: MINIMO_NOTA })}
        </span>
      </label>
      {erro && (
        <p className="campo__erro" role="alert">
          {erro}
        </p>
      )}
      <div className="decisao__acoes">
        <button type="submit" className="botao botao--primario" disabled={enviando}>
          {tipo === "corrigir" ? t("salvarCorrecao") : t("confirmarDescarte")}
        </button>
        <button type="button" className="botao botao--fantasma" onClick={aoCancelar}>
          {t("cancelar")}
        </button>
      </div>
    </form>
  );
}
