# Identity and Access API

Este projeto implementa uma **API de autenticação e validação de credenciais** baseada em Active Directory, em um **único projeto ASP.NET Core** (`src/IdentityAndAccess.Api`), sem camadas separadas: os controllers chamam diretamente os serviços de Active Directory.

## Estrutura

```
src/IdentityAndAccess.Api
├── Controllers/                  AuthController (POST /api/v1/auth/validate), UsersController (GET /api/v1/users)
├── Models/                       Requests/responses e os modelos de usuário do AD (AdUser, AdUserDetails)
├── Services/                     IActiveDirectoryAuthService / IActiveDirectoryUsersService e implementações
│   └── ActiveDirectory/          Descoberta de controladores de domínio, política de senha e leitura de atributos
├── Options/                      DirectoryServicesOptions, AuthRateLimitOptions
├── Exceptions/                   DirectoryUnavailableException (vira 503)
└── Program.cs                    Registro de serviços e pipeline
```

## NuGets utilizados

- **Rkd.Scalar** (2.8.1): pacote do próprio autor — documentação interativa (Scalar), versionamento, autenticação Basic, erros padronizados no formato **RFC 9457** (`application/problem+json` com `code` e `traceId`) e **log HTTP** em fila assíncrona.
- **Rkd.Scalar.HttpLogging.SqlServer**: destino SQL Server do log HTTP do Rkd.Scalar.
- **System.DirectoryServices.AccountManagement**: acesso ao Active Directory.

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
