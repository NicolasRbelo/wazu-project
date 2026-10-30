import { useIdioma, type Idioma } from "../i18n";

const OPCOES: { valor: Idioma; sigla: string; nome: string }[] = [
  { valor: "pt", sigla: "PT", nome: "Português" },
  { valor: "en", sigla: "EN", nome: "English" },
];

export function TrocaIdioma() {
  const { idioma, trocar, t } = useIdioma();
  return (
    <div className="troca-idioma" role="group" aria-label={t("idioma")}>
      {OPCOES.map((opcao) => (
        <button
          key={opcao.valor}
          type="button"
          lang={opcao.valor}
          aria-pressed={idioma === opcao.valor}
          aria-label={opcao.nome}
          onClick={() => trocar(opcao.valor)}
        >
          {opcao.sigla}
        </button>
      ))}
    </div>
  );
}
