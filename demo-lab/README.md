# demo-lab

**Celowo podatne** usługi do pokazania pełnej ścieżki Sentinel ASI. Wszystkie dane tutaj są
fikcyjne. Nie uruchamiaj tych kontenerów w żadnej innej konfiguracji niż ta z
`docker-compose.yml`.

## Izolacja

- sieć Dockera `demo-lab` ma `internal: true`: kontenery nie mają wyjścia na zewnątrz,
- żaden kontener demo-lab nie publikuje portów na hoście,
- do sieci jest podłączony wyłącznie skaner (`worker-scans`); API, baza i interfejs jej nie widzą,
- usługi startują tylko z profilem `demo` (`docker compose --profile demo up`).

## Co tu jest

| Adres | Usługa | W inwentarzu (`assets.csv`) | Co pokazuje |
|---|---|---|---|
| 172.30.99.10 | Apache httpd 2.4.49 | web-01, internet, krytyczność 5 | CVE z katalogu KEV, alert natychmiastowy |
| 172.30.99.11 | nginx 1.18.0 | proxy-01, internet, krytyczność 4 | dopasowanie przez alias (CPE z nmap różni się od NVD) |
| 172.30.99.12 | DVWA (Apache 2.4.25 z Debiana) | legacy-01, wewnętrzny | pakiet dystrybucji: kolejka weryfikacji zamiast zgadywania |
| 172.30.99.13 | OWASP Juice Shop | shop-01, internet | usługa bez rozpoznanego produktu |
| 172.30.99.14 | Redis 5.0.7 | brak | shadow IT: host odpowiada, a nie ma go w inwentarzu |
| 172.30.99.20 | nic | old-db-01 | zasób z inwentarza, który nie odpowiada |

## Uruchomienie

```bash
./scripts/seed_demo.sh
```

Skrypt wymaga `DEMO_MODE=true` w `.env` i sam niczego w tym pliku nie zmienia.
