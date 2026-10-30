import { MotionConfig } from "motion/react";
import { useCallback, useState } from "react";
import { CHAVE_TOKEN, gravar, ler } from "./armazenamento";
import { Conectar } from "./componentes/Conectar";
import { Painel } from "./componentes/Painel";
import { ProvedorIdioma } from "./i18n";

export function App() {
  const [token, setToken] = useState<string | null>(() => ler("sessao", CHAVE_TOKEN));
  const [expirou, setExpirou] = useState(false);

  const conectar = useCallback((novo: string) => {
    gravar("sessao", CHAVE_TOKEN, novo);
    setExpirou(false);
    setToken(novo);
  }, []);

  const sair = useCallback((porRecusa: boolean) => {
    gravar("sessao", CHAVE_TOKEN, null);
    setExpirou(porRecusa);
    setToken(null);
  }, []);

  return (
    <ProvedorIdioma>
      {/* reducedMotion="user": quem pede menos movimento no sistema recebe trocas instantâneas */}
      <MotionConfig reducedMotion="user">
        {token ? (
          <Painel token={token} aoSair={sair} />
        ) : (
          <Conectar aoConectar={conectar} expirou={expirou} />
        )}
      </MotionConfig>
    </ProvedorIdioma>
  );
}
