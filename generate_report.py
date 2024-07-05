import json
from datetime import datetime

# Génère un rapport HTML basé sur les résultats de vérification de mot de passe et de scan réseau
def generate_html_report(
    password_results_file="resultat_verification_mot_de_passe.json",
    network_scan_file="scan_results.json",
):
    try:
        # Lecture des résultats de vérification de mot de passe
        with open(password_results_file, "r", encoding="utf-8") as file:
            password_data = json.load(file)

        mot_de_passe_valide = password_data.get("mot_de_passe_valide", False)
        mot_de_passe_compromis = password_data.get("mot_de_passe_compromis", False)
        recommandations_durete = password_data.get("recommandations_durete", [])
        recommandation_compromis = password_data.get("recommandation_compromis", "")

        # Lecture des résultats de scan réseau
        with open(network_scan_file, "r", encoding="utf-8") as file:
            network_data = json.load(file)

        gateway_ip = network_data.get("gateway_ip", "Non déterminé")
        gateway_hostname = network_data.get("gateway_hostname", "Nom d'hôte inconnu")
        scan_results = network_data.get("results", {})
        client_count = len(scan_results)

        filename = datetime.now().strftime("rapport_du_scan.html")

        # Génération du fichier HTML
        with open(filename, "w", encoding="utf-8") as report_file:
            report_file.write(
                f"""
<!DOCTYPE html>
<html lang='fr'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Rapport Toolbox</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{
            font-family: Arial, sans-serif;
        }}
        .container {{
            margin-top: 20px;
        }}
        .recommendations {{
            background-color: #f9f9f9;
            border-left: 6px solid #cc0000;
            padding: 10px 20px;
        }}
        pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .expand-btn {{
            cursor: pointer;
            color: #007bff;
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class='container'>
        <h1 class='text-center text-primary'>Rapport de la Toolbox</h1>
        <ul class="nav nav-tabs" id="myTab" role="tablist">
            <li class="nav-item">
                <a class="nav-link active" id="password-tab" data-toggle="tab" href="#password" role="tab" aria-controls="password" aria-selected="true">Conformité du mot de passe</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" id="network-tab" data-toggle="tab" href="#network" role="tab" aria-controls="network" aria-selected="false">Scans Réseau</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" id="security-tab" data-toggle="tab" href="#security" role="tab" aria-controls="security" aria-selected="false">CVE</a>
            </li>
        </ul>
        <div class="tab-content" id="myTabContent">
            <div class="tab-pane fade show active" id="password" role="tabpanel" aria-labelledby="password-tab">
                <div class='card my-4'>
                    <div class='card-header'>
                        <h2>Validité du mot de passe :</h2>
                    </div>
                    <div class='card-body'>
                        <p class='card-text'>{'Valide' if mot_de_passe_valide else 'Non valide'}</p>
                    </div>
                </div>
                <div class='card my-4'>
                    <div class='card-header'>
                        <h2>Mot de passe compromis :</h2>
                    </div>
                    <div class='card-body'>
                        <p class='card-text'>{'Oui' if mot_de_passe_compromis else 'Non'}</p>
                        <p class='card-text'>{recommandation_compromis}</p>
                    </div>
                </div>
                <div class='card my-4'>
                    <div class='card-header'>
                        <h2>Recommandations pour le mot de passe :</h2>
                    </div>
                    <div class='card-body recommendations'>
                        {"<p>" + "</p><p>".join(recommandations_durete) + "</p>" if recommandations_durete else "<p>Aucune recommandation supplémentaire.</p>"}
                    </div>
                </div>
            </div>
            <div class="tab-pane fade" id="network" role="tabpanel" aria-labelledby="network-tab">
                <div class='card my-4'>
                    <div class='card-header'>
                        <h2>Résumé du Scan Réseau :</h2>
                    </div>
                    <div class='card-body'>
                        <p class='card-text'>IP du Routeur/Passerelle : {gateway_ip} ({gateway_hostname})</p>
                        <p class='card-text'>Nombre de Clients : {client_count}</p>
                    </div>
                </div>
                <h2>Détails des Clients</h2>
                <table class='table table-bordered'>
                    <thead class='thead-dark'>
                        <tr><th>Adresse IP</th><th>Nom d'Hôte</th><th>Résultat du Scan Nmap</th><th>Vérification de Port</th><th>Capture de Trafic</th></tr>
                    </thead>
                    <tbody>
                    """
            )

            for ip, info in scan_results.items():
                host_name = info.get("host_name", "Nom d'hôte inconnu")
                nmap_result = info.get("nmap_result", "Non effectué").replace("\n", "<br>")
                port_check_result = info.get("port_check_result", "Non effectué").replace("\n", "<br>")
                traffic_capture_file = info.get("traffic_capture_file", "Non effectué")
                traffic_capture_link = (
                    f'<a href="{traffic_capture_file}" download>Télécharger</a>'
                    if traffic_capture_file != "Non effectué"
                    else "Non effectué"
                )
                report_file.write(
                    f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{host_name}</td>
                        <td>
                            <div class="text-preview" style="display:none;">{nmap_result}</div>
                            <div class="text-preview-short">{'<br>'.join(nmap_result.split('<br>')[:5])}</div>
                            <span class="expand-btn">Voir plus</span>
                        </td>
                        <td>
                            <div class="text-preview" style="display:none;">{port_check_result}</div>
                            <div class="text-preview-short">{'<br>'.join(port_check_result.split('<br>')[:5])}</div>
                            <span class="expand-btn">Voir plus</span>
                        </td>
                        <td>{traffic_capture_link}</td>
                    </tr>
                    """
                )

            report_file.write(
                """
                    </tbody>
                </table>
            </div>
            <div class="tab-pane fade" id="security" role="tabpanel" aria-labelledby="security-tab">
                <div class='card my-4'>
                    <div class='card-header'>
                        <h2>Résultats de Sécurité</h2>
                    </div>
                    <div class='card-body'>
                        <h2>Détails des CVE</h2>
                        <table class='table table-bordered'>
                            <thead class='thead-dark'>
                                <tr><th>Adresse IP</th><th>Port</th><th>Service</th><th>Version</th><th>CVE</th><th>Résumé</th></tr>
                            </thead>
                            <tbody>
                """
            )

            for ip, info in scan_results.items():
                versions = info.get("versions", {})
                cve_results = info.get("cve_results", {})
                for port, cves in cve_results.items():
                    service = versions.get(port, {}).get('service', 'N/A')
                    version = versions.get(port, {}).get('version', 'N/A')
                    for cve in cves:
                        if isinstance(cve, dict):
                            cve_id = cve.get('id', 'N/A')
                            cve_summary = cve.get('summary', 'N/A')
                        else:
                            cve_id = "N/A"
                            cve_summary = cve
                        report_file.write(
                            f"""
                            <tr>
                                <td>{ip}</td>
                                <td>{port}</td>
                                <td>{service}</td>
                                <td>{version}</td>
                                <td>{cve_id}</td>
                                <td>{cve_summary}</td>
                            </tr>
                            """
                        )

            report_file.write(
                """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        <button id="saveAsPDF" class="btn btn-primary">Sauvegarder en PDF</button>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.9.2/html2pdf.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script>
        window.onload = function () {
            document.getElementById('saveAsPDF').addEventListener('click', function () {
                var element = document.body;
                var opt = {
                    margin: 0.5,
                    filename: `rapport_scan_reseau_${new Date().toISOString().slice(0,10)}.pdf`,
                    image: { type: 'jpeg', quality: 0.98 },
                    html2canvas: { scale: 2 },
                    jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' }
                };
                html2pdf().set(opt).from(element).save();
            });

            document.querySelectorAll('.expand-btn').forEach(function(button) {
                button.addEventListener('click', function() {
                    var shortPreview = this.previousElementSibling;
                    var fullPreview = shortPreview.previousElementSibling;
                    if (fullPreview.style.display === 'none') {
                        fullPreview.style.display = 'block';
                        shortPreview.style.display = 'none';
                        this.textContent = 'Voir moins';
                    } else {
                        fullPreview.style.display = 'none';
                        shortPreview.style.display = 'block';
                        this.textContent = 'Voir plus';
                    }
                });
            });
        }
    </script>
</body>
</html>
"""
            )
            print(f"Rapport HTML combiné généré avec succès : {filename}")
    except Exception as e:
        print(f"Erreur lors de la génération du rapport combiné : {e}")

if __name__ == "__main__":
    generate_html_report()
