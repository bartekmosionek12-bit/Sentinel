import os
from pathlib import Path

# Testy działają poza kontenerem: reguły (w tym rules/roles.yaml) z katalogu repozytorium.
# Ustawiane przed importem aplikacji, bo `require()` czyta katalog ról przy imporcie tras.
os.environ.setdefault("RULES_DIR", str(Path(__file__).resolve().parents[2] / "rules"))
