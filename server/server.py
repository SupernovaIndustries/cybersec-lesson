#!/usr/bin/env python3
# server_vulnerabile.py - Un server Flask vulnerabile per dimostrazioni
# ATTENZIONE: Questo server contiene vulnerabilità INTENZIONALI.
# Usare SOLO per scopi educativi in un ambiente controllato.

from flask import Flask, request, render_template_string
import os
import subprocess

app = Flask(__name__)

# Template HTML base
BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Server Vulnerabile Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #333; }
        pre { background-color: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .container { max-width: 800px; margin: 0 auto; }
        form { margin-bottom: 20px; }
        input[type="text"] { padding: 8px; width: 300px; }
        button { padding: 8px 15px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        .warning { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Server Vulnerabile Demo</h1>
        <p class="warning">ATTENZIONE: Questo server contiene vulnerabilità INTENZIONALI. Da utilizzare solo per scopi educativi!</p>

        <h2>Funzionalità Disponibili:</h2>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/ping">Ping Tool</a> (Vulnerabile a Command Injection)</li>
            <li><a href="/search">Ricerca</a> (Vulnerabile a XSS)</li>
        </ul>

        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""


# Home page
@app.route('/')
def home():
    template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
    <h2>Benvenuto nel Server Vulnerabile Demo</h2>
    <p>Questo server è stato creato per scopi educativi per mostrare comuni vulnerabilità web.</p>
    <p>Utilizza i link sopra per esplorare le diverse funzionalità vulnerabili.</p>
    """)
    return render_template_string(template)


# Endpoint vulnerabile a Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ""
    if request.method == 'POST':
        host = request.form.get('host', 'localhost')

        # VULNERABILE: Command Injection
        # L'input dell'utente viene direttamente inserito in un comando di sistema
        # Un utente malintenzionato potrebbe inserire "localhost; ls -la" per eseguire comandi arbitrari
        try:
            # NON FARE MAI QUESTO IN PRODUZIONE!
            command = f"ping -c 3 {host}"
            result = os.popen(command).read()
        except Exception as e:
            result = f"Errore: {str(e)}"

    template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
    <h2>Ping Tool</h2>
    <p>Inserisci un hostname o indirizzo IP da pingare:</p>
    <form method="post">
        <input type="text" name="host" placeholder="Esempio: localhost" required>
        <button type="submit">Ping</button>
    </form>

    {% if result %}
    <h3>Risultato:</h3>
    <pre>{{ result }}</pre>
    {% endif %}

    <h3>Vulnerabilità: Command Injection</h3>
    <p>Questo endpoint è vulnerabile a command injection perché l'input dell'utente viene 
    direttamente inserito in un comando shell senza sanitizzazione.</p>
    <p><strong>Esempio di attacco:</strong> Prova a inserire <code>localhost; ls -la</code></p>
    """)

    return render_template_string(template, result=result)


# Endpoint vulnerabile a XSS
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    result = ""

    if query:
        # VULNERABILE: Cross-Site Scripting (XSS)
        # L'input dell'utente viene direttamente inserito nell'HTML senza sanitizzazione
        result = f"<p>Hai cercato: {query}</p><p>Nessun risultato trovato.</p>"

    template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
    <h2>Ricerca</h2>
    <p>Cerca qualcosa nel nostro database:</p>
    <form method="get">
        <input type="text" name="query" placeholder="Termine di ricerca..." required>
        <button type="submit">Cerca</button>
    </form>

    {% if result %}
    <h3>Risultati:</h3>
    {{ result|safe }}
    {% endif %}

    <h3>Vulnerabilità: Cross-Site Scripting (XSS)</h3>
    <p>Questo endpoint è vulnerabile a XSS perché l'input dell'utente viene 
    direttamente inserito nell'HTML senza sanitizzazione.</p>
    <p><strong>Esempio di attacco:</strong> Prova a inserire <code>&lt;script&gt;alert('XSS!')&lt;/script&gt;</code></p>
    """)

    return render_template_string(template, result=result)


# Versione sicura dell'endpoint ping
@app.route('/ping_sicuro', methods=['GET', 'POST'])
def ping_sicuro():
    result = ""
    if request.method == 'POST':
        host = request.form.get('host', 'localhost')

        # SICURO: Utilizza subprocess con parametri separati
        # Inoltre, validazione dell'input con controllo whitelist
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+$', host):
            result = "Input non valido. Solo lettere, numeri, punti e trattini sono permessi."
        else:
            try:
                # Approccio sicuro: subprocess con lista di argomenti
                result = subprocess.check_output(['ping', '-c', '3', host],
                                                 stderr=subprocess.STDOUT,
                                                 timeout=5).decode()
            except subprocess.CalledProcessError as e:
                result = f"Errore: {e.output.decode()}"
            except subprocess.TimeoutExpired:
                result = "Timeout durante l'esecuzione del ping"

    template = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
    <h2>Ping Tool (Versione Sicura)</h2>
    <p>Inserisci un hostname o indirizzo IP da pingare:</p>
    <form method="post">
        <input type="text" name="host" placeholder="Esempio: localhost" required>
        <button type="submit">Ping</button>
    </form>

    {% if result %}
    <h3>Risultato:</h3>
    <pre>{{ result }}</pre>
    {% endif %}

    <h3>Protezione applicata</h3>
    <p>Questo endpoint è protetto contro command injection tramite:</p>
    <ol>
        <li>Validazione dell'input (whitelist di caratteri consentiti)</li>
        <li>Utilizzo di subprocess con lista di argomenti anziché una stringa di comando</li>
    </ol>
    """)

    return render_template_string(template, result=result)


if __name__ == '__main__':
    print("ATTENZIONE: Questo server contiene vulnerabilità INTENZIONALI!")
    print("Da utilizzare solo per scopi educativi in un ambiente controllato.")
    print("Server in esecuzione su http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)