import { LockKey } from "@phosphor-icons/react";
import { useState, type FormEvent } from "react";
import { api, ErroApi, ErroRede } from "../api";
import { useIdioma } from "../i18n";
import { TrocaIdioma } from "./TrocaIdioma";

export function Conectar({ aoConectar, expirou }: { aoConectar: (token: string) => void; expirou: boolean }) {
  const { t } = useIdioma();
  const [token, setToken] = useState("");
  const [testando, setTestando] = useState(false);
  const [erro, setErro] = useState<string | null>(expirou ? t("sessaoExpirada") : null);

  async function enviar(evento: FormEvent) {
    evento.preventDefault();
    const valor = token.trim();
    if (!valor) return;
    setTestando(true);
    setErro(null);
    try {
      await api.listarAlertas(valor);
      aoConectar(valor);
    } catch (falha) {
      if (falha instanceof ErroApi && falha.status === 401) setErro(t("tokenRecusado"));
      else if (falha instanceof ErroRede) setErro(t("erroRede"));
      else if (falha instanceof ErroApi) setErro(t("erroGenerico", { status: falha.status }));
      setTestando(false);
    }
  }

  return (
    <div className="conectar">
      <header className="barra">
        <span className="barra__marca">wazuh-triagem</span>
        <div className="barra__direita">
          <TrocaIdioma />
        </div>
      </header>
      <main className="conectar__palco">
        <form className="conectar__faixa" onSubmit={enviar}>
          <div className="conectar__designador" aria-hidden="true">
            <LockKey size={28} weight="bold" />
          </div>
          <div className="conectar__corpo">
            <h1>{t("conectarTitulo")}</h1>
            <p className="conectar__texto">{t("conectarTexto")}</p>
            <label className="campo" htmlFor="token">
              <span className="campo__rotulo">{t("token")}</span>
              <input
                id="token"
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={token}
                onChange={(e) => setToken(e.target.value)}
                aria-invalid={erro ? true : undefined}
                aria-describedby={erro ? "token-erro" : undefined}
                autoFocus
              />
            </label>
            {erro && (
              <p id="token-erro" className="campo__erro" role="alert">
                {erro}
              </p>
            )}
            <button className="botao botao--primario" type="submit" disabled={testando || !token.trim()}>
              {testando ? t("conectando") : t("conectar")}
            </button>
          </div>
        </form>
      </main>
    </div>
  );
}
