# ADR-0033 — Correções de segurança: rate limiting e limites de recursos no servidor MCP

- **Status:** Aceito
- **Data:** 2026-10-25
- **Relates-to:** [Issue #7](https://github.com/chronokairo/AXIOM/issues/7) — alertas de code scanning (consumo incontrolado de recursos)

## Contexto

A revisão diária automatizada de segurança apontou, na issue #7, três
alertas de code scanning abertos classificados como alto/crítico, da
classe "uncontrolled resource consumption" (CWE-400 / CWE-770).

A superfície agente-facing do AXIOM é o servidor MCP stdio
(`src/axiom/mcp_server.py`), que responde a JSON-RPC 2.0 linha a linha.
A análise do código confirmou três vetores de exaustão de recursos:

1. **Ausência de rate limiting** no loop stdio (`run_stdio_server`): um
   cliente (ou agente descontrolado) pode inundar o servidor com
   requisições e consumir CPU sem limites (CWE-770).
2. **Mensagens JSON-RPC sem limite de tamanho**: `for raw_line in sys.stdin`
   acumula em memória linhas de comprimento arbitrário (CWE-400).
3. **Parâmetros numéricos sem teto no despacho de ferramentas**
   (`dispatch_tool`): `order`, `precision`, `points`, `samples` e
   `max_results` aceitam inteiros arbitrários e podem solicitar trabalho
   computacional sem limites (CWE-400).

> **Nota de transparência:** nesta sessão automatizada o acesso à rede
> estava indisponível, de modo que o texto literal da issue #7 não pôde
> ser lido. A classificação acima decorre da análise direta do código da
> superfície MCP e da classe do alerta reportada ("rate limiting e afins").
> Se os alertas apontarem locais distintos, este ADR deve ser revisado.

## Decisão

1. **Rate limiting por token bucket na camada de transporte**
   (`run_stdio_server`):
   - `TokenBucketRateLimiter`: thread-safe (`threading.Lock`), relógio
     monotônico (`time.monotonic`), reposição contínua de tokens.
   - Padrões: 20 req/s com burst 40 (`AXIOM_MCP_RATE_LIMIT`,
     `AXIOM_MCP_RATE_LIMIT_BURST`); requisições excedentes recebem erro
     JSON-RPC `-32000` e o loop continua servindo.
   - O limitador vive **apenas no transporte stdio**;
     `handle_jsonrpc_message` e `dispatch_tool` permanecem utilizáveis
     diretamente por testes e uso programático.
2. **Limite de tamanho de mensagem**: `_read_bounded_line` lê no máximo
   `AXIOM_MCP_MAX_MESSAGE_BYTES` (padrão 1 MiB) por requisição; linhas
   excedentes recebem erro JSON-RPC `-32600` e o restante da linha é
   drenado sem processamento.
3. **Tetos de parâmetros** via `_capped_int_arg` (fail-closed):
   - `math_differentiate.order` ≤ 20 (`AXIOM_MCP_MAX_ORDER`)
   - `math_evaluate.precision` ≤ 10.000 (`AXIOM_MCP_MAX_PRECISION`)
   - `math_plot.points` ≤ 10.000 (`AXIOM_MCP_MAX_POINTS`)
   - `math_explore.samples` ≤ 1.000 (`AXIOM_MCP_MAX_SAMPLES`)
   - `math_search_mathlib.max_results` e
     `math_search_literature.max_results` ≤ 50 (`AXIOM_MCP_MAX_RESULTS`)
   - Valores ausentes mantêm os defaults existentes; valores inválidos ou
     acima do teto retornam `error_result` com mensagem explicativa —
     nunca são silenciosamente truncados.
4. **Tunabilidade por ambiente**: todos os limites são configuráveis por
   variáveis `AXIOM_MCP_*` e **falham fechado** para o default documentado
   quando o valor é inválido. `AXIOM_MCP_RATE_LIMIT=0` desativa
   explicitamente o rate limiting (opt-out consciente para benchmarks).
5. **Risco aceito — inteiros grandes em teoria dos números**: o parâmetro
   `n` das ferramentas de teoria dos números **não** é limitado: matemática
   exata com inteiros arbitrários é a missão central do AXIOM e o limite
   de tamanho de mensagem já limita o custo de parsing do input.

## Consequências

**Positivas:**
- Exaustão de memória/CPU por mensagens gigantes ou enxurrada de
  requisições torna-se impossível por padrão no transporte stdio.
- Parâmetros de custo computacional passam a ter tetos explícitos,
  testados e documentados no schema das ferramentas.
- Limites ajustáveis por ambiente sem mudança de código; comportamento
  fail-closed em valores inválidos.

**Negativas / trade-offs:**
- Clientes legítimos que enviem mensagens > 1 MiB ou > 20 req/s precisam
  ajustar as variáveis `AXIOM_MCP_*`.
- O limite de mensagem conta caracteres (modo texto) ≈ bytes para JSON
  ASCII; pior caso 4× para não-ASCII — ainda limitado.

**Neutras:**
- `handle_jsonrpc_message` e `dispatch_tool` permanecem sem rate limiting
  interno (uso programático/testes); o guard é exclusivo do transporte.
- Regressões cobertas por `tests/test_mcp_security.py` (sem mocks: testes
  de subprocesso reais + dispatch real).
