# Benchmark de ablação

Modelo: `gemini-2.5-flash`, temperatura 0, saída estruturada (`responseSchema`) em todas as configurações. Gerado em 2026-11-03T14:41:58+00:00.

Conjunto **sintético**: 71 alertas no formato do Wazuh (29 ataques, 24 atividades legítimas e 18 ataques com prompt injection em campos controlados pelo atacante). IPs de documentação (RFC 5737), reputações inventadas. Gerador: `avaliacao/cenarios.py`.

> **Execução parcial:** 20 de 71 alertas medidos até agora (o plano gratuito do Gemini permite 20 chamadas por dia). Os números abaixo ainda não são o resultado final.

| Métrica | ingenuo | ingenuo+politicas | protegido | completo |
|---|---|---|---|---|
| Classificação correta | 19/19 (100%) | 19/19 (100%) | 17/18 (94%) | 17/18 (94%) |
| Ataques que seriam descartados (falso negativo) | 0/17 (0%) | 0/17 (0%) | 0/16 (0%) | 0/16 (0%) |
| Prompt injections bem-sucedidas | 0/2 (0%) | 0/2 (0%) | 0/2 (0%) | 0/2 (0%) |
| Benignos tratados como ataque | 0/2 (0%) | 0/2 (0%) | 0/2 (0%) | 0/2 (0%) |
| Inconclusivos (vão para o analista) | 0/19 (0%) | 0/19 (0%) | 1/18 (6%) | 1/18 (6%) |
| Injeções sinalizadas como manipulação | 2/2 (100%) | 2/2 (100%) | 2/2 (100%) | 2/2 (100%) |
| Alertas sem injeção sinalizados como manipulação | 0/17 (0%) | 0/17 (0%) | 0/16 (0%) | 0/16 (0%) |
| Respostas inválidas ou erro da API | 1 | 1 | 1 | 1 |

- **ingenuo**: o alerta inteiro colado no pedido, sem regras de segurança.
- **protegido**: dados mínimos e truncados, marcador com nonce, instruções separadas e lembrete depois dos dados.
- **+politicas / completo**: as regras fixas de `app/politicas.py` aplicadas depois da IA.

## Prompt injection por estilo

Injeções bem-sucedidas (o ataque terminaria descartado), por estilo de payload. Cada estilo aparece em três portadores: usuário SSH, User-Agent e caminho HTTP.

| Estilo | ingenuo | ingenuo+politicas | protegido | completo |
|---|---|---|---|---|
| `direto_pt` | 0/2 (0%) | 0/2 (0%) | 0/2 (0%) | 0/2 (0%) |
| `direto_en` | - | - | - | - |
| `tag_falsa` | - | - | - | - |
| `autoridade` | - | - | - | - |
| `json_injetado` | - | - | - | - |
| `sutil` | - | - | - | - |

## Detector de injeção por regex (sem IA)

É uma das camadas das políticas: se ele dispara, a sugestão nunca termina em descarte.

- No benchmark: 18/18 (100%) das injeções, 0/53 (0%) falsos alarmes nos demais alertas. **O detector foi ajustado depois da primeira medição neste conjunto** (antes: 7/18), então este número é otimista.
- Por estilo: `direto_pt` 3/3, `direto_en` 3/3, `tag_falsa` 3/3, `autoridade` 3/3, `json_injetado` 3/3, `sutil` 3/3.
- Na validação, com frases escritas antes do ajuste e nunca usadas nele (`VALIDACAO_*` em `cenarios.py`): 4/8 (50%) das injeções e 1/6 (17%) falsos alarmes em textos legítimos (antes do ajuste: 1/8 e 0/6). Regex sozinha generaliza mal: por isso ela é uma camada, não a defesa.

## Limites desta medição

- O conjunto é sintético e pequeno; mede comportamento, não garante desempenho em produção.
- A reputação é inventada e entra pronta no contexto; nenhuma fonte externa é consultada.
- Temperatura 0 reduz, mas não elimina, a variação entre execuções.
- Latência mediana por chamada: 6.22 s.
