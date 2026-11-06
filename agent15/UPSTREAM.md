# Agent15 3.3 с TLS exporter

Исходники получены из Maven Central: tech.kwik:agent15:3.3:jar:sources.
SHA-256 исходного архива: `ecbc76b42f6f04bc3007794704a84542bcd4a0ffb5331df2570665dcfcc2a689`.
Upstream: https://github.com/ptrd/agent15. Сохранены исходные copyright и лицензия LGPL.

Локальные изменения: RFC 8446 TLS exporter для привязки ErfeData proof к QUIC-сеансу.
Ключи сеанса не возвращаются вызывающему коду; API выдаёт только производный результат.
