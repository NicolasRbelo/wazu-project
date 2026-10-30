import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// O proxy mantém a API em 127.0.0.1 e dispensa CORS: o navegador só fala com o Vite.
// WAZUH_TRIAGEM_API troca o destino (ex.: uma API de demonstração em outra porta).
const alvo = process.env.WAZUH_TRIAGEM_API ?? "http://127.0.0.1:8000";
const proxy = { "/api": alvo };

export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5173, proxy },
  preview: { host: "127.0.0.1", port: 4173, proxy },
});
