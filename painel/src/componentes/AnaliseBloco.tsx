import { WarningOctagon } from "@phosphor-icons/react";
import { useIdioma, type Chave, type Grupo } from "../i18n";
import type { Analise, Correcao } from "../tipos";
import { dataHora } from "../util";

interface Props {
  analise: Analise | null | undefined;
  analisando: boolean;
  erro: string | null;
}

const LINHAS: { campo: keyof Correcao; grupo: Grupo; chave: Chave }[] = [
  { campo: "classificacao", grupo: "classificacao", chave: "classificacao" },
  { campo: "severidade", grupo: "severidade", chave: "severidade" },
  { campo: "acao_sugerida", grupo: "acao", chave: "acao" },
];

/** T1110.001 vira /techniques/T1110/001/. O backend já garantiu o formato do ID. */
const urlMitre = (id: string) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

export function AnaliseBloco({ analise, analisando, erro }: Props) {
  const { t, rotulo, idioma } = useIdioma();

  return (
    <section className="bloco bloco--largo analise" aria-labelledby="analise-titulo" aria-busy={analisando || analise === undefined}>
      <div className="bloco__cabeca">
        <h2 id="analise-titulo">{t("sugestao")}</h2>
        {analise && (
          <span className="analise__modelo mono">
            {t("modelo", { modelo: analise.modelo, quando: dataHora(analise.criada_em, idioma) })}
          </span>
        )}
      </div>

      {erro && (
        <p className="campo__erro" role="alert">
          {erro}
        </p>
      )}

      {analise === undefined || (analise === null && analisando) ? (
        <EsqueletoChaves rotulo={analisando ? t("analisando") : t("carregando")} />
      ) : analise === null ? (
        <p className="bloco__vazio">
          {t("semAnaliseTexto")} {t("analisarDica")}
        </p>
      ) : (
        <>
          {analise.sugestao.indicios_manipulacao && (
            <p className="aviso-perigo">
              <WarningOctagon size={18} weight="bold" aria-hidden="true" />
              {t("manipulacaoAviso")}
            </p>
          )}

          <div className="chaves" role="table" aria-label={t("sugestao")}>
            <div className="chaves__linha chaves__linha--cabeca" role="row">
              <span role="columnheader" className="chaves__ia">
                {t("iaDisse")}
              </span>
              <span role="columnheader" className="chaves__chave" />
              <span role="columnheader" className="chaves__final">
                {t("final")}
              </span>
            </div>
            {LINHAS.map(({ campo, grupo, chave }) => {
              const daIa = analise.sugestao_ia[campo];
              const final = analise.sugestao[campo];
              const doAnalista = analise.correcao?.[campo];
              return (
                <div className="chaves__linha" role="row" key={campo}>
                  {/* Nada some, cancela: o que a política trocou fica riscado. */}
                  <span role="cell" className="chaves__ia">
                    {daIa !== final ? <s>{rotulo(grupo, daIa)}</s> : rotulo(grupo, daIa)}
                  </span>
                  <span role="rowheader" className="chaves__chave">
                    {t(chave)}
                  </span>
                  <span role="cell" className="chaves__final">
                    {doAnalista && doAnalista !== final ? (
                      <>
                        <s>{rotulo(grupo, final)}</s>
                        <strong>{rotulo(grupo, doAnalista)}</strong>
                        <span className="chaves__marca">{t("analista")}</span>
                      </>
                    ) : (
                      rotulo(grupo, final)
                    )}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="analise__texto">
            {/* Saída do modelo: também é texto, nunca HTML. */}
            <p className="analise__resumo">{analise.sugestao.resumo}</p>
            <p className="analise__justificativa">{analise.sugestao.justificativa}</p>
            <div className="analise__rodape">
              <span className="mono">{t("confianca", { n: analise.sugestao.confianca })}</span>
              {analise.sugestao.tecnicas_mitre.map((id) => (
                <a key={id} className="mitre mono" href={urlMitre(id)} target="_blank" rel="noopener noreferrer">
                  {id}
                </a>
              ))}
            </div>
          </div>

          <div className="ajustes">
            <h3>{t("ajustes")}</h3>
            {analise.ajustes.length > 0 ? (
              <ul>
                {analise.ajustes.map((ajuste) => (
                  <li key={ajuste}>{ajuste}</li>
                ))}
              </ul>
            ) : (
              <p className="bloco__vazio">{t("semAjustes")}</p>
            )}
          </div>

          {analise.nota && (
            <div className="nota-analista">
              <h3>{t("notaAnalista")}</h3>
              <p>{analise.nota}</p>
            </div>
          )}
        </>
      )}
    </section>
  );
}

function EsqueletoChaves({ rotulo }: { rotulo: string }) {
  return (
    <div className="chaves chaves--esqueleto" role="status" aria-label={rotulo}>
      {[0, 1, 2].map((i) => (
        <div className="chaves__linha" key={i}>
          <span className="esqueleto" />
          <span className="chaves__chave" />
          <span className="esqueleto" />
        </div>
      ))}
      <span className="chaves__esqueleto-rotulo">{rotulo}</span>
    </div>
  );
}
