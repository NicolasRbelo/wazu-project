# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Vite + React + TypeScript for the triage panel (`painel/`), consuming the existing FastAPI backend (`app/`) over HTTP with a Bearer token. Backend: FastAPI, SQLAlchemy 2.0, Pydantic, SQLite, httpx. Windows dev environment, Python 3.11.

## Users

Primary: a SOC tier-1 / blue-team analyst triaging Wazuh alerts in a lab, deciding quickly whether each alert is real, what to do about it, and whether to accept the AI's suggestion. Secondary: recruiters and engineers evaluating the project as a GitHub portfolio piece. The analyst's workflow comes first; the panel should still read as carefully made to someone seeing it for the first time.

## Product Purpose

wazuh-triagem receives Wazuh alerts, enriches the source IP with AbuseIPDB and VirusTotal, and asks an LLM (Google Gemini) for a structured triage suggestion. The panel is where a human reviews each alert with its evidence and approves, corrects, or discards the suggestion. Success: an analyst can clear a queue of alerts faster, with the evidence for every decision on screen, and never has an alert closed by the AI alone.

## Positioning

The AI only suggests; a human decides. Alert content is treated as attacker-controlled data: the backend isolates it from the model's instructions, validates the model's output, and applies fixed code-level policies afterwards (a suggestion can never be "false positive" or "discard" when there are signs of prompt injection or the IP has bad reputation). The panel makes that visible: what the AI said, what the policies changed and why, and what the analyst finally decided.

## Operating Context

- Alerts arrive from a Wazuh 4.14 manager (Docker lab) through a custom integration script, or are sent manually from `exemplos/`.
- API runs locally (`python run.py`, default `127.0.0.1:8000`); all routes require `Authorization: Bearer <API_TOKEN>`.
- Existing endpoints: `GET /api/alertas`, `GET /api/alertas/{id}/reputacao`, `POST /api/alertas/{id}/analise` (`?refazer=true` to redo), `GET /api/alertas/{id}/analise`.
- Analysis takes several seconds (LLM call) and consumes free-tier quota; reputation lookups are cached for 24h and only run for public IPs.
- Lab alerts use documentation IP ranges, so reputation usually shows "not public / not queried".

## Capabilities and Constraints

- Alert fields: id, wazuh_id, rule_id, rule_level (0-15), rule_description, agent_name, srcip, full_log, recebido_em (UTC).
- Reputation per source has a status: `ok`, `nao_configurado`, `limite_excedido`, `erro`. AbuseIPDB: score 0-100, total reports, whitelist, Tor, country, ISP. VirusTotal: malicious / suspicious / harmless / undetected engines, reputation, AS owner.
- Analysis: classificacao (verdadeiro_positivo / falso_positivo / inconclusivo), severidade (baixa / media / alta / critica), confianca 0-100, acao_sugerida (bloquear_ip / investigar / monitorar / descartar), resumo, justificativa, tecnicas_mitre, indicios_manipulacao; plus `sugestao_ia` (raw model answer), `sugestao` (after policies), `ajustes` (list of explanations), `revisao` (pendente / aprovada / corrigida / descartada).
- The analyst review endpoint (approve / correct / discard) does not exist yet and is part of this stage.
- `full_log`, decoded fields, and text from reputation sources (ISP, AS owner) are untrusted: render as inert text only, never as HTML.
- UI language: Portuguese and English, switchable by the user. API values stay in Portuguese and are mapped to display labels.

## Brand Commitments

Project name: wazuh-triagem. User-stated binding direction for the panel: a HUD / operations-console feel, visually pleasing, and it must not look AI-generated or templated.

## Evidence on Hand

- Example alerts with fictitious data: `exemplos/alerta_ssh.json`, `exemplos/alerta_injecao.json` (prompt injection in the SSH username).
- Attack simulator for the lab: `lab/simular_ataque.py`.
- Real validated results exist only from local runs (Gemini resisted the injection example). There are no users, metrics, or testimonials; none may be invented.

## Product Principles

1. Human decides, AI suggests: every AI output is presented as a proposal with its reasoning and the analyst's action is the final word.
2. Show the evidence, not just the verdict: reputation, raw log, and policy adjustments sit next to the suggestion.
3. Untrusted data looks and behaves like data: attacker-controlled text is visibly marked and never interpreted.
4. Speed for the queue: the common path (read, decide, next) takes few clicks and works from the keyboard.
5. Honest states: loading, quota exhausted, source not configured, and errors are shown plainly, never hidden or faked.

## Accessibility & Inclusion

No product-specific requirement established beyond WCAG AA contrast and keyboard operability for the triage flow.
