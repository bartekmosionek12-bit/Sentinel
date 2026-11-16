# Dane testowe

Wszystkie pliki w tym katalogu są **fikcyjne lub ręcznie przygotowane** na potrzeby testów
i demonstracji. Nie są kopią feedów ani wynikami skanów prawdziwej infrastruktury.

- `nmap_*.xml`: syntetyczne wyniki nmap dla adresów z izolowanej sieci demo-lab
  (`172.30.99.0/24`), w formacie zgodnym z `nmap -oX`.
- `feeds/`: miniaturowy zestaw w formatach NVD 2.0, CISA KEV i EPSS. Zawiera kilka
  publicznie znanych identyfikatorów CVE dotyczących oprogramowania z demo-lab, żeby dało
  się pokazać pełną ścieżkę bez internetu. Opisy są skrócone, a wartości EPSS przykładowe.
  Do prawdziwej pracy służy `scripts/fetch_feeds.sh`, który pobiera aktualne dane poza Gitem.

Limit: kilkadziesiąt KB na plik. Prawdziwe snapshoty feedów i wyniki skanów nie trafiają
do repozytorium.
