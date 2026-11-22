"""Wiedza techniczna Sentka: jak skanować, co znaczą flagi nmap, porty, sygnatury.

Odpowiedzi są stałym tekstem w kodzie, sprawdzonym z konfiguracją (`rules/discovery.yaml`)
i z tym, co silnik naprawdę uruchamia. Nie ma tu modelu językowego ani danych z bazy, więc
odpowiedź nie zależy od uprawnień do wyników. Wartości domyślne i limity bierzemy z pliku
reguł w chwili odpowiedzi, żeby tekst nie rozjechał się z konfiguracją.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.assistant.text import has_stem, normalize, words


@dataclass(frozen=True)
class Topic:
    key: str
    stems: tuple[str, ...]
    title: str


# Kolejność rozstrzyga remisy: pierwszy temat z największą liczbą trafień wygrywa.
TOPICS: tuple[Topic, ...] = (
    Topic(
        "port_info",
        ("do czego sluzy port", "co to za port", "jaka usluga", "co nasluchuje", "port uslugi"),
        "Do czego służy port",
    ),
    Topic(
        "nmap_flags",
        ("nmap", "parametr", "max-rate", "-sn", "-sv", "-pe", "-ps", "-pn", "szablon czas"),
        "Jak Sentinel wywołuje nmap",
    ),
    Topic(
        "typical_scans",
        (
            "typow",
            "przyklad",
            "przykladow",
            "jak skanowac",
            "jak zeskanowac",
            "jak ustawic skan",
            "konfiguracj",
            "ustawienia skanu",
            "duza siec",
            "duzej sieci",
            "ile workerow",
            "jakie ustawienia",
            "skan nocn",
        ),
        "Typowe skany i ich ustawienia",
    ),
    Topic(
        "tuning",
        (
            "wolno",
            "szybciej",
            "przyspiesz",
            "wydajnos",
            "tempo",
            "dlugo trwa",
            "za dlugo",
            "ile potrwa",
            "ile trwa",
            "paczk",
        ),
        "Tempo skanu i jak je dobrać",
    ),
    Topic(
        "troubleshooting",
        (
            "nie widzi",
            "nie wykrywa",
            "nie znalazl",
            "zero hostow",
            "tylko jeden",
            "brak hostow",
            "icmp",
            "firewall",
            "zapor",
            "nie odpowiada",
        ),
        "Dlaczego host nie pojawia się w wynikach",
    ),
    Topic(
        "signature_howto",
        ("napisac sygnatur", "nowa sygnatur", "wlasna sygnatur", "yaml", "regul detekc"),
        "Własna sygnatura: przykład",
    ),
    Topic(
        "schedule_howto",
        ("harmonogram", "okno czasow", "w nocy", "noca", "jednorazow", "wznow", "cyklicz"),
        "Harmonogram i skan jednorazowy",
    ),
    Topic(
        "scope_howto",
        ("zakres", "scope", "poza zakresem", "odrzucon", "zablokowan", "scope_guard", "ipv6"),
        "Zakres skanowania i scope_guard",
    ),
    Topic(
        "export_formats",
        ("eksport", "format", "csv", "json", "xml", "pobierz wynik", "raport z przebiegu"),
        "Eksport wyników",
    ),
    Topic(
        "host_states_help",
        ("co znaczy niestabiln", "stany hosta", "co to aktywny", "kiedy nieaktywny"),
        "Stany hostów",
    ),
)
TOPIC_KEYS = tuple(t.key for t in TOPICS)

# Porty spotykane w sieciach organizacji: usługa, typowe oprogramowanie, na co uważać.
PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "Logowanie i dane jawnym tekstem; anonimowy dostęp to częsty błąd."),
    22: (
        "SSH",
        "Zdalna administracja. Sprawdź wersję OpenSSH i czy logowanie hasłem jest wyłączone.",
    ),
    23: (
        "Telnet",
        "Jawny tekst, nie powinien być wystawiony; spotykany na starym sprzęcie sieciowym.",
    ),
    25: ("SMTP", "Serwer poczty; otwarty relay to ryzyko spamu."),
    53: ("DNS", "Resolver albo serwer autorytatywny; otwarty resolver bywa nadużywany."),
    80: ("HTTP", "Strona bez TLS; sprawdź przekierowanie na HTTPS i panele pod /admin, /login."),
    81: ("HTTP (alternatywny)", "Często panel proxy (np. Nginx Proxy Manager)."),
    110: ("POP3", "Poczta jawnym tekstem bez STARTTLS."),
    135: ("MS RPC", "Windows; nie powinien być widoczny poza siecią serwerową."),
    139: ("NetBIOS", "Stary Windows/Samba; ujawnia nazwy hostów."),
    143: ("IMAP", "Poczta; sprawdź STARTTLS."),
    443: ("HTTPS", "Sprawdź certyfikat (wygasanie, samopodpisany) i nagłówki bezpieczeństwa."),
    445: ("SMB", "Udziały plików Windows/Samba; nie wystawiaj poza LAN."),
    993: ("IMAPS", "Poczta po TLS."),
    1433: ("MS SQL Server", "Baza danych; nie powinna być osiągalna z sieci użytkowników."),
    2222: ("SSH (alternatywny)", "Często SSH kontenera albo Gitea."),
    3000: ("HTTP aplikacji", "Typowo Gitea, Grafana albo aplikacja Node.js w trybie dev."),
    3306: ("MySQL/MariaDB", "Baza danych; dostęp tylko z sieci aplikacji."),
    3389: ("RDP", "Pulpit zdalny Windows; częsty cel ataków, nie wystawiaj publicznie."),
    5000: ("HTTP aplikacji", "Flask, rejestr Dockera albo panel NAS."),
    5432: ("PostgreSQL", "Baza danych; dostęp tylko z sieci aplikacji."),
    5601: ("Kibana", "Panel Elastic; bez logowania ujawnia logi."),
    5672: ("AMQP (RabbitMQ)", "Kolejka komunikatów; domyślne konto guest bywa włączone."),
    5900: ("VNC", "Pulpit zdalny, często bez szyfrowania."),
    6379: ("Redis", "Bez hasła pozwala czytać i zapisywać dane; nie wystawiaj."),
    8000: ("HTTP aplikacji", "Serwery deweloperskie (Django, uvicorn); często staging."),
    8080: ("HTTP (proxy/aplikacja)", "Tomcat, Jenkins, proxy; sprawdź panele administracyjne."),
    8081: ("HTTP aplikacji", "Nexus, panele narzędzi, DefectDojo w tym projekcie."),
    8443: ("HTTPS (alternatywny)", "Panele urządzeń i aplikacji; sprawdź certyfikat."),
    8474: ("Toxiproxy API", "Narzędzie testowe; nie powinno działać poza labem."),
    8888: ("HTTP aplikacji", "Jupyter Notebook; bez tokenu pozwala uruchamiać kod."),
    9000: ("HTTP aplikacji", "Portainer, SonarQube, MinIO; panele administracyjne."),
    9090: ("HTTP aplikacji", "Prometheus albo Cockpit; ujawnia metryki."),
    9200: ("Elasticsearch", "API bez uwierzytelnienia ujawnia indeksy."),
    15672: ("Panel RabbitMQ", "Panel zarządzania kolejką; sprawdź konto guest."),
    27017: ("MongoDB", "Baza bez uwierzytelnienia to częsty wyciek danych."),
}


def find_topic(text: str) -> str | None:
    tokens = words(text)
    raw = normalize(text)
    best, score = None, 0
    for topic in TOPICS:
        hits = sum(
            1 if s.startswith("-") and s in raw.split() else 0 for s in topic.stems
        ) + has_stem(tokens, [s for s in topic.stems if not s.startswith("-")])
        if hits > score:
            best, score = topic.key, hits
    return best


def title(key: str) -> str:
    return next(t.title for t in TOPICS if t.key == key)


def _defaults(config: Any) -> tuple[Any, dict[str, int]]:
    return config.defaults, dict(config.limits)


def answer(
    key: str, config: Any, port: int | None = None
) -> tuple[list[str], list[dict[str, str]]]:
    """Tekst i linki dla tematu. `config` to DiscoveryConfig (wartości domyślne i limity)."""
    d, limits = _defaults(config)
    max_workers = limits.get("workers", 16)
    max_rate = limits.get("max_rate", 2000)
    if key == "port_info":
        if port is None:
            return (
                [
                    "Podaj numer portu, np. „do czego służy port 5672?”. Znam typowe porty "
                    "usług spotykanych w sieciach organizacji.",
                ],
                [],
            )
        known = PORTS.get(port)
        lines = (
            [f"Port {port}/tcp: {known[0]}. {known[1]}"]
            if known
            else [
                f"Portu {port} nie ma w mojej liście typowych usług. Rozpoznanie usługi daje "
                "nmap -sV w skanie usług: sprawdź kolumnę Usługi przy hoście."
            ]
        )
        lines.append(
            "Które hosty mają go otwartego, pokażę po pytaniu „pokaż urządzenia z otwartym "
            f"portem {port}”."
        )
        return lines, [{"label": "Discovery", "to": "/discovery"}]
    if key == "nmap_flags":
        return (
            [
                "Sentinel uruchamia nmap w dwóch fazach, zawsze przez scope_guard i tylko na "
                "zatwierdzonym zakresie:",
                f"1. Sweep (paczki CIDR): `nmap -sn -n -PE -PS<porty> -T{d.timing} "
                f"--max-rate {d.max_rate} -oX -`. -sn to wykrywanie hostów bez skanu portów, "
                "-n wyłącza DNS, -PE to ICMP echo, -PS to TCP SYN na porty wykrywania "
                "(hosty, które blokują ICMP, i tak odpowiedzą).",
                f"2. Usługi (pojedynczy host): `nmap -sV -Pn -n -T{d.timing} --max-rate "
                f"{d.max_rate} -p <porty usług> --open -oX -`. -sV rozpoznaje usługę i wersję, "
                "-Pn pomija ponowny ping (host już odpowiedział), --open zapisuje tylko otwarte.",
                f"-T jest ograniczone do 0–{limits.get('timing', 3)} (T4 i T5 zablokowane), "
                f"--max-rate do {max_rate} pakietów/s na proces, workerów najwyżej "
                f"{max_workers}. Nie ma skanów UDP, skryptów NSE ani prób logowania.",
                "Na usługach WWW działa jeszcze fingerprint HTTP: jedno GET na stronę główną "
                "i ścieżki z sygnatur (np. /admin, /login), bez wysyłania danych.",
            ],
            [{"label": "Nowy przebieg", "to": "/discovery"}],
        )
    if key == "typical_scans":
        return (
            [
                "Typowe skany (Discovery → Nowy przebieg; wartości to workery / pakiety na "
                "sekundę na worker / szablon -T):",
                f"• Jedna podsieć /24 w dzień: {d.workers} / {d.max_rate} / T{d.timing} "
                "(domyślne). Trwa około minuty plus skan usług aktywnych hostów.",
                "• Sieć /18 (16 tys. adresów) w oknie nocnym: 8–16 / 500–1000 / T3, harmonogram "
                "22:00–06:00. Paczki same dobiorą rozmiar (16–1024 adresy).",
                f"• Sieć /16 (65 tys. adresów, limit jednego przebiegu to "
                f"{limits.get('addresses', 70000):,}".replace(",", " ")
                + f"): {max_workers} / 1000 / T3 w harmonogramie nocnym. Jeśli nie zdąży, "
                "zapisze resztę i dokończy następnej nocy.",
                "• Łącze VPN albo słaba sieć oddziału: 2 / 100 / T2. Wolniej, ale bez gubienia "
                "odpowiedzi i bez obciążania łącza.",
                "• Lista domen i pojedynczych serwerów: wklej po jednym w wierszu; każda domena "
                "jest rozwiązywana i sprawdzana przez scope_guard (IPv4 i IPv6).",
                "• Szybki test po zmianie w sieci: tylko zmieniony zakres, potem Porównanie z "
                "poprzednim przebiegiem pokaże nowe i zniknięte hosty oraz usługi.",
            ],
            [
                {"label": "Nowy przebieg", "to": "/discovery"},
                {"label": "Harmonogram", "to": "/discovery/harmonogram"},
            ],
        )
    if key == "tuning":
        return (
            [
                "Czas skanu zależy głównie od liczby adresów, aktywnych hostów i tempa sieci, "
                "nie od Pythona: nmap (C/C++) wysyła pakiety, Python tylko układa paczki.",
                "• Sweep: łączne tempo to workery × --max-rate. Gdy paczki trwają długo, a "
                "sieć to wytrzymuje, podnieś workery, potem tempo.",
                "• Skan usług trwa najdłużej (kilka sekund na host). Mniej portów usług = "
                "szybciej; więcej workerów skanuje więcej hostów naraz.",
                "• Rośnie liczba niepotwierdzonych hostów albo odpowiedzi znikają: obniż tempo "
                "albo -T. Zgubione odpowiedzi wyglądają jak hosty niestabilne.",
                "• ETA na stronie przebiegu liczy się z mierzonej szybkości ostatnich paczek. "
                "Zbyt długi skan ustaw w harmonogramie z oknem; po końcu okna stan zostanie "
                "zapisany.",
            ],
            [{"label": "Przebiegi", "to": "/discovery"}],
        )
    if key == "troubleshooting":
        return (
            [
                "Najczęstsze powody, dla których host nie pojawia się w wynikach:",
                "1. Host blokuje ICMP i nie słucha na żadnym porcie wykrywania. Dodaj jego "
                "typowy port do discovery_ports w rules/discovery.yaml albo wpisz adres jako /32.",
                "2. Cel poza zatwierdzonym zakresem: scope_guard odrzuca całą paczkę albo host "
                "(widać to w paczkach przebiegu i w dzienniku audytu).",
                "3. Skan przez NAT (Docker Desktop, VPN): widzisz jeden adres bramy, a usługi "
                "labu jako porty tego jednego hosta. To poprawne zachowanie.",
                "4. Zbyt wysokie tempo na słabym łączu gubi odpowiedzi. Obniż --max-rate; host "
                "widziany poprzednio dostaje i tak drugą próbę (/32) w tym samym przebiegu.",
                "5. Host działa tylko w dzień albo tylko w nocy: zobaczysz to w stanie hosta "
                "(etykieta pory dnia).",
            ],
            [{"label": "Zakres", "to": "/zakres"}, {"label": "Przebiegi", "to": "/discovery"}],
        )
    if key == "signature_howto":
        return (
            [
                "Sygnatura w YAML mówi tylko, czego szukać w odpowiedzi GET. Przykład panelu:",
                "```yaml\nid: grafana-login\nname: Grafana – logowanie\nkind: panel\nmatch:\n"
                '  - {type: title, pattern: "grafana"}\n'
                '  - {type: cookie, pattern: "^grafana_session$"}\n'
                '  - {type: path, path: /login, status: [200], pattern: "grafana"}\n```',
                "Typy dopasowań: header, cookie, favicon_hash, html, title, generator, path. "
                "Rodzaj: technology, panel albo staging. Wystarczy jedno dopasowanie.",
                "Przycisk „Testuj” sprawdza sygnaturę od razu na zapisanym przebiegu, bez "
                "ruchu w sieci (html i treść ścieżki sprawdzi dopiero kolejny skan).",
            ],
            [{"label": "Sygnatury", "to": "/discovery/sygnatury"}],
        )
    if key == "schedule_howto":
        return (
            [
                "Harmonogram ma dwa tryby:",
                "• Cykliczny: częstotliwość (np. codziennie), okno czasowe (np. 22:00–06:00, "
                "przez północ), dni tygodnia i strefa. Start tylko w oknie.",
                "• Jednorazowy: dokładna data i godzina startu oraz końca.",
                "Gdy koniec wybije przed końcem skanu, rozpoczęte paczki są dokończone, a "
                "niezeskanowane zakresy i hosty bez skanu usług zapisane (status Wstrzymany). "
                "Cykliczny wznowi je sam w kolejnym oknie, jednorazowy po kliknięciu „Wznów”.",
                "Godzinę końca można też podać przy zwykłym przebiegu (pole „Zakończ najpóźniej”).",
            ],
            [{"label": "Harmonogram", "to": "/discovery/harmonogram"}],
        )
    if key == "scope_howto":
        return (
            [
                "Każde działanie sieciowe przechodzi przez scope_guard: paczka CIDR, pojedynczy "
                "host, domena po rozwiązaniu, ponowna próba /32 i fingerprint HTTP.",
                "Zakres to plik rules/scope.*.yaml (allow/deny CIDR i domen) zatwierdzony przez "
                "administratora. Deny wygrywa z allow, a domena musi mieć wszystkie adresy w "
                "zakresie (IPv4 i IPv6).",
                "Przed startem „Sprawdź cele” pokazuje dla każdego celu decyzję i powód. "
                "Odrzucenia trafiają do dziennika audytu.",
                "Docker Desktop: host.docker.internal ma też adres IPv6; jeśli nie jest w "
                "zakresie, cel zostanie odrzucony. Użyj adresu IPv4 albo dodaj IPv6 do zakresu.",
            ],
            [{"label": "Zakres", "to": "/zakres"}, {"label": "Dziennik audytu", "to": "/audyt"}],
        )
    if key == "export_formats":
        return (
            [
                "Wyniki przebiegu pobierzesz ze strony przebiegu:",
                "• JSON: pełne dane hostów, usług, fingerprintu HTTP, flag i stanów.",
                "• CSV: jeden wiersz na usługę (host, port, produkt, wersja, flagi), do Excela.",
                "• nmap XML: zgodny z nmap -oX, do innych narzędzi.",
                "• Porównanie dwóch przebiegów: JSON albo CSV z nowymi, zniknętymi i "
                "zmienionymi hostami i usługami.",
                "• DefectDojo: zaznaczone hosty jako findings (Engagement „Sprint final”).",
            ],
            [{"label": "Przebiegi", "to": "/discovery"}],
        )
    # host_states_help
    return (
        [
            "Stan hosta liczę z ostatnich przebiegów obejmujących jego adres:",
            "• aktywny: odpowiedział w ostatnim przebiegu,",
            "• niestabilny: w ostatnich 5 przebiegach odpowiedzi przeplatają się z ich brakiem,",
            "• niepotwierdzony: nie odpowiedział ostatnio, ale braków jest mniej niż 3,",
            "• nieaktywny: 3 kolejne przebiegi bez odpowiedzi.",
            "Przebieg wstrzymany na końcu okna nie liczy się jako brak odpowiedzi.",
        ],
        [{"label": "Discovery", "to": "/discovery"}],
    )
