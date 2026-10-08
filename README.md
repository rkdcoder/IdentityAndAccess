# Identity and Access API

Este projeto implementa uma **API de autenticação e validação de credenciais** baseada em Active Directory, estruturada segundo os princípios de **DDD (Domain-Driven Design)**, **CQRS (Command Query Responsibility Segregation)** e **Arquitetura Hexagonal**.

## Arquitetura

- **DDD (Domain-Driven Design)**: separação clara das camadas de **Domain**, **Application**, **Infrastructure** e **Api**, garantindo que a lógica de negócio (regras de domínio) permaneça isolada e independente de tecnologias externas.
- **CQRS (Command Query Responsibility Segregation)**: uso de _commands_ e _queries_ distintos para operações de escrita e leitura, implementados com **Cqrsly**, garantindo clareza e melhor escalabilidade no fluxo da aplicação.
- **Arquitetura Hexagonal (Ports & Adapters)**: aplicação organizada em **ports** (interfaces) e **adapters** (implementações), permitindo substituir facilmente dependências externas como Active Directory ou provedores de persistência.

## NuGets utilizados

Este projeto utiliza pacotes desenvolvidos pelo próprio autor:

- **Cqrsly**: responsável pelo _dispatcher_ CQRS, inspirado no MediatR, mas minimalista e de alta performance. Ele organiza o fluxo entre _commands_, _queries_ e _handlers_.
- **Rkd.Scalar** (2.8.1): documentação interativa (Scalar), versionamento, autenticação Basic, erros padronizados no formato **RFC 9457** (`application/problem+json` com `code` e `traceId`) e **log HTTP** em fila assíncrona.
- **Rkd.Scalar.HttpLogging.SqlServer**: destino SQL Server do log HTTP do Rkd.Scalar.

## Configuração (`appsettings.json`)

| Seção | Uso |
| ----- | --- |
| `Credentials` | `Username`/`Password` usados no Basic da API (`/api/v1/users`) e na proteção da UI do Scalar. |
| `DirectoryServices` | `ContextOptions` e `TimeoutSeconds` (timeout de descoberta/consulta ao AD). |
| `RateLimiting:AuthValidate` | Limite por IP de `POST /api/v1/auth/validate` (`PermitLimit` por `WindowSeconds`); excedido → `429` com `Retry-After`. Atrás de proxy/balanceador, habilite `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` para limitar pelo IP real do cliente. |
| `ConnectionStrings:Logs` | Banco onde o log HTTP é gravado. |
| `HttpLogging` | Opções do log HTTP (`MaxBodyBytes`, `ExcludedPaths`, `SensitivePaths`…) e `SqlServer` (`Table`, `CreateTable`). |

### Log HTTP

Cada requisição é gravada (fora do caminho da requisição) em `logs.HttpRequests`, com `TraceId` — o mesmo `traceId` devolvido nas respostas de erro —, status, duração, rota, usuário, `ErrorCode` e exceção não tratada. Com `CreateTable: true` a tabela é criada na primeira gravação; sem permissão de DDL, execute uma vez `SqlServerHttpLogTable.CreateScript("logs.HttpRequests")`.

Os corpos de `POST /api/v1/auth/validate` (contém a senha) e de `GET /api/v1/users` (dados pessoais) **nunca** são gravados (`[SensitiveHttpLog]` + `SensitivePaths`).

### Erros

| Situação | Resposta |
| -------- | -------- |
| Dados inválidos | `400`, `code: VALIDATION_ERROR`, `errors` por campo |
| Sem/errada credencial Basic | `401` |
| Limite de tentativas por IP excedido | `429`, `code: TOO_MANY_REQUESTS` |
| Credenciais de AD inválidas | `401` com `success: false` e a mensagem do motivo |
| Nenhum controlador de domínio respondeu | `503`, `code: DIRECTORY_UNAVAILABLE` |
| Erro inesperado | `500`, `code: ERRO_INESPERADO` (sem detalhes fora de Development) |

> A API usa `System.DirectoryServices` e, por isso, só executa no **Windows**.

## Objetivo

O objetivo principal deste código é disponibilizar um **endpoint de autenticação** que:

- Recebe credenciais (usuário, senha e domínio/AD);
- Valida diretamente contra o **Active Directory**;
- Retorna informações detalhadas do usuário quando autenticado;
- Fornece respostas padronizadas com status apropriados (200, 400, 401, 429, 503);
- Mantém a aplicação escalável, modular e aderente a boas práticas de arquitetura moderna.

---

⚡ Resultado: uma API organizada, extensível, segura e pronta para rodar em ambientes corporativos de alta complexidade.
