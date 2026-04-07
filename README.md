# Identity and Access API

Este projeto implementa uma **API de autenticação e validação de credenciais** baseada em Active Directory, estruturada segundo os princípios de **DDD (Domain-Driven Design)**, **CQRS (Command Query Responsibility Segregation)** e **Arquitetura Hexagonal**.

## Arquitetura

- **DDD (Domain-Driven Design)**: separação clara das camadas de **Domain**, **Application**, **Infrastructure** e **Api**, garantindo que a lógica de negócio (regras de domínio) permaneça isolada e independente de tecnologias externas.
- **CQRS (Command Query Responsibility Segregation)**: uso de _commands_ e _queries_ distintos para operações de escrita e leitura, implementados com **Cqrsly**, garantindo clareza e melhor escalabilidade no fluxo da aplicação.
- **Arquitetura Hexagonal (Ports & Adapters)**: aplicação organizada em **ports** (interfaces) e **adapters** (implementações), permitindo substituir facilmente dependências externas como Active Directory ou provedores de persistência.

## NuGets utilizados

Este projeto utiliza três pacotes desenvolvidos pelo próprio autor:

- **Cqrsly**: responsável pelo _dispatcher_ CQRS, inspirado no MediatR, mas minimalista e de alta performance. Ele organiza o fluxo entre _commands_, _queries_ e _handlers_.
- **Rkd.Scalar**: simplifica a configuração do **Scalar** entregando rapidamente documentação interativa e suporte a autenticação.
- **Rkd.ApiException**: middleware que padroniza as respostas de erro da API, fornecendo mensagens consistentes, `traceId` para rastreabilidade e logging com rotação automática de arquivos.

## Objetivo

O objetivo principal deste código é disponibilizar um **endpoint de autenticação** que:

- Recebe credenciais (usuário, senha e domínio/AD);
- Valida diretamente contra o **Active Directory**;
- Retorna informações detalhadas do usuário quando autenticado;
- Fornece respostas padronizadas com status apropriados (200, 401, 404);
- Mantém a aplicação escalável, modular e aderente a boas práticas de arquitetura moderna.

---

⚡ Resultado: uma API organizada, extensível, segura e pronta para rodar em ambientes corporativos de alta complexidade.
