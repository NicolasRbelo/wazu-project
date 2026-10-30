import { useIdioma } from "../i18n";
import type { Alerta, Reputacao, ResultadoFonte } from "../tipos";

export type EstadoReputacao = "ocioso" | "carregando" | "erro";

interface Props {
  alerta: Alerta;
  reputacao: Reputacao | null;
  estado: EstadoReputacao;
  erro: string | null;
  aoConsultar: () => void;
}

// Mesmos limites de app/politicas.py: acima deles o IP conta como malicioso.
const SCORE_MALICIOSO = 75;
const MOTORES_MALICIOSO = 3;

const numero = (valor: unknown) => (typeof valor === "number" ? valor : 0);
const texto = (valor: unknown) => (typeof valor === "string" && valor.trim() ? valor : null);

export function ReputacaoBloco({ alerta, reputacao, estado, erro, aoConsultar }: Props) {
  const { t } = useIdioma();

  let conteudo;
  if (!alerta.srcip) {
    conteudo = <p className="bloco__vazio">{t("semIp")}</p>;
  } else if (estado === "carregando") {
    conteudo = (
      <div className="reputacao__fontes" aria-busy="true">
        <div className="esqueleto esqueleto--bloco" />
        <div className="esqueleto esqueleto--bloco" />
      </div>
    );
  } else if (reputacao === null) {
    conteudo = (
      <div className="reputacao__pedir">
        {erro && (
          <p className="campo__erro" role="alert">
            {erro}
          </p>
        )}
        <p className="bloco__vazio">{t("reputacaoDica")}</p>
        <button type="button" className="botao" onClick={aoConsultar}>
          {t("consultarReputacao")}
        </button>
      </div>
    );
  } else if (!reputacao.publico) {
    conteudo = (
      <p className="bloco__vazio">
        <span className="mono">{reputacao.ip}</span> {t("ipNaoPublico")}
      </p>
    );
  } else {
    conteudo = (
      <div className="reputacao__fontes">
        <Fonte nome="AbuseIPDB" resultado={reputacao.fontes.abuseipdb}>
          {(dados) => {
            const score = numero(dados.score);
            const extras = [
              t("denuncias", { n: numero(dados.total_denuncias) }),
              dados.na_whitelist ? t("naWhitelist") : t("foraWhitelist"),
              dados.tor ? t("tor") : null,
            ].filter(Boolean);
            const terceiro = [texto(dados.isp), texto(dados.pais)].filter(Boolean).join(", ");
            return (
              <>
                <span
                  className={`reputacao__numero mono${score >= SCORE_MALICIOSO && !dados.na_whitelist ? " reputacao__numero--ruim" : ""}`}
                >
                  {score}
                  <small>/100</small>
                </span>
                <span className="reputacao__linha">{extras.join(", ")}</span>
                {terceiro && <span className="reputacao__terceiro">{terceiro}</span>}
              </>
            );
          }}
        </Fonte>
        <Fonte nome="VirusTotal" resultado={reputacao.fontes.virustotal}>
          {(dados) => {
            const maliciosos = numero(dados.maliciosos);
            const total =
              maliciosos + numero(dados.suspeitos) + numero(dados.inofensivos) + numero(dados.nao_detectados);
            const terceiro = [texto(dados.dono_as), texto(dados.pais)].filter(Boolean).join(", ");
            return (
              <>
                <span className={`reputacao__numero mono${maliciosos >= MOTORES_MALICIOSO ? " reputacao__numero--ruim" : ""}`}>
                  {maliciosos}
                  <small>/{total}</small>
                </span>
                <span className="reputacao__linha">
                  {t("motoresMaliciosos")}, {t("suspeitos", { n: numero(dados.suspeitos) })}
                </span>
                {terceiro && <span className="reputacao__terceiro">{terceiro}</span>}
              </>
            );
          }}
        </Fonte>
      </div>
    );
  }

  return (
    <section className="bloco reputacao" aria-labelledby="reputacao-titulo">
      <h2 id="reputacao-titulo">{t("reputacao")}</h2>
      {conteudo}
    </section>
  );
}

function Fonte({
  nome,
  resultado,
  children,
}: {
  nome: string;
  resultado: ResultadoFonte | undefined;
  children: (dados: Record<string, unknown>) => React.ReactNode;
}) {
  const { t } = useIdioma();
  let corpo;
  if (!resultado || resultado.status === "nao_configurado") corpo = <span className="reputacao__linha">{t("fonteNaoConfigurada")}</span>;
  else if (resultado.status === "limite_excedido") corpo = <span className="reputacao__linha">{t("fonteLimite")}</span>;
  else if (resultado.status === "erro" || !resultado.dados)
    corpo = <span className="reputacao__linha">{t("fonteErro", { erro: resultado.erro ?? "?" })}</span>;
  else corpo = children(resultado.dados);

  return (
    <div className="reputacao__fonte">
      <span className="reputacao__nome">
        {nome}
        {resultado?.em_cache && <span className="reputacao__cache">{t("doCache")}</span>}
      </span>
      {corpo}
    </div>
  );
}
