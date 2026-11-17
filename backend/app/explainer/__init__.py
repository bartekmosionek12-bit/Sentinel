"""AI Explainer: jedyny moduł, który rozmawia z modelem językowym.

Model niczego nie decyduje. Dostaje fakty złożone przez kod z bazy i formułuje z nich
tekst dla człowieka. Każdą odpowiedź sprawdza deterministyczny walidator; odpowiedź,
która nie przejdzie, jest zastępowana wyjaśnieniem z szablonu.
"""
