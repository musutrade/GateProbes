# HTTP JSON contract collector — 0.1.0 release candidate

Independent Harness-Gate adapter-v2 plugin. Core owns policy and signature checks.
It measures `contract.breaking_changes`, `contract.client_drift`, and
`contract.compatible` from a separately trusted initial baseline, current declared
contract, actual Angular TypeScript AST, and host-recorded live HTTP responses.
All source/capture inputs and baseline bytes are pinned in the signed binding.

Supported scope is deliberately explicit: the bounded OpenAPI 3.0.3 business
contracts and canonical Angular consumers described below. Every declared HTTP
status must have a live response observation. Unknown schema/client features,
missing variants or invalid provider responses fail collection, never become zero.
The host must independently inventory approved consumer source files and protect
HTTP capture provenance from repository tests; the receipt alone is not isolation.

Existing operation changes are conservatively counted as incompatible. This is
not a general OpenAPI compatibility engine; a compatible evolution outside this
subset requires a reviewed new series. Additional operations require complete
observations. Initial baseline establishment is distinct from claiming a prior
released API. Baseline updates require host policy approval.

Artifacts use an exclusive component subdirectory under Core's shared root.
No signing keys, policy overrides or Core source imports are included.

The `generate SPEC TYPE_NAME OUTPUT` command emits a response interface stamped
with the exact contract SHA-256. Collection retains both the checked-in generated
type and the current expected generated type. It rejects forged stamps or types
edited without regeneration; a recognized older baseline stamp is reported as
client drift. This satisfies Core's generated-client provenance contract without
changing Core. Formatting differences are normalized through the TypeScript AST.

## Business JSON contracts (candidate rc.4)

The bounded OpenAPI 3.0.3 adapter supports GET/POST/PUT/PATCH/DELETE, declared
path/query/header parameters, JSON request bodies, closed nested objects, arrays,
string/boolean/number/integer fields, enums, nullable fields and local acyclic
component schema references. Unsupported schema features fail closed. Every
response status for every declared operation requires a real observation.
No-content responses are represented by an absent OpenAPI content member and
an observation with a null body and empty content type.

`generate` now emits all operation response types in one generated type file;
`getHealth` retains `HealthResponse`, other operations use PascalCase operationId
plus `Response` (and `Request` for JSON request bodies). The complete source digest
stamp is retained. The checker rejects edited/widened types, `any`, TypeScript
suppression comments, missing consumers and undeclared operations.
All expected declarations are compared in both directions, including JSON
Request types and Response types with no current call site. Field types,
requiredness and enum changes cannot be hidden by retaining declaration names
or the digest stamp. Whitespace-only formatting remains accepted.

Supported Angular forms are canonical `httpResource<T>(() => '/literal')` and
`HttpClient` held in an explicitly typed/injected variable or class property,
using typed get/post/put/patch/delete calls with literal or template paths.
Dynamic/aliased HTTP APIs require an additional certified adapter; they are not
silently ignored. Parameter templates must resolve to one declared route shape.
Every use of a canonical `httpResource` binding must be its import declaration
or a direct call. Assigning it to a variable/property, passing or returning it,
re-exporting it, shadowing its name, and indirect calls fail inventory, including
in files alongside an otherwise valid consumer.
Request examples are checked against request schemas for successful responses;
response types are checked structurally against generated operation types.

This is a new measurement series. Installation requires a freshly validated host
approval; it must not replace rc.3 in place or reuse an old series identity.

## Functional interceptor imports (candidate rc.5)

Canonical `HttpInterceptorFn` (including type-only imports) and `withInterceptors`
imports from `@angular/common/http` are accepted. Interceptor type declarations
and provider registration are not counted as HTTP calls. The inventory still
traverses interceptor bodies and counts their typed `HttpClient` calls; undeclared
routes, aliases, indirect client use, `fetch`, and unsupported HTTP imports retain
their existing rejection or drift behavior.

Only the import allowlist and collector version change. Request/response schemas,
complete provider status coverage, generated-type checks and baseline comparison
retain the rc.4 implementation. Install rc.5 separately and approve its new
measurement-series identity; do not overwrite an existing rc.4 installation or
reuse the old series pin. Rollback selects the preserved rc.4 installation and
its matching approved series, but restores the functional-import rejection.

Signed candidate packages and installation: [release guide](https://github.com/musutrade/Harness-Gate/blob/main/docs/releases/0.4.8.zh-CN.md).

GH-282 strengthens those existing inventory and generated-type checks. The rule
identity includes the collector implementation hash and therefore changes with
this repair. New collection requires the matching approved series; previous
evidence must retain its original identity.

## Stable acceptance boundary

Version 0.1.0 changes collector identity only; capabilities and dependencies are unchanged. Publication requires fresh exact-head/main CI and installed-package contract acceptance against pinned released Core v0.6.0. Independent download acceptance must verify the actual published bytes, dependency isolation, inventory and provenance. Linux x86_64/Node24 acceptance does not claim a production deployment or additional platforms. Previous RC artifacts and historical acceptance remain unchanged.
