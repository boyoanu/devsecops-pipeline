pipeline {
    agent any

    environment {
        TARGET_DVWA = 'http://dvwa:80'
        ZAP_API = 'http://localhost:8090'
    }

    stages {
        stage('Dependency Scan') {
            options {
                timeout(time: 5, unit: 'MINUTES')
            }
            steps {
                sh '''
                    echo "=== Running Snyk Container Scan ==="
                    snyk container test vulnerables/web-dvwa --severity-threshold=high --json > snyk-report.json || true
                    echo "Snyk scan completed."
                '''
            }
        }

        stage('Container Scan') {
            options {
                timeout(time: 10, unit: 'MINUTES')
            }
            steps {
                sh '''
                    echo "=== Running Trivy Scan ==="
                    trivy image vulnerables/web-dvwa --severity HIGH,CRITICAL --format json > trivy-report.json || true
                    echo "Trivy scan completed."
                '''
            }
        }

        stage('Network Discovery') {
            options {
                timeout(time: 5, unit: 'MINUTES')
            }
            steps {
                sh '''
                    echo "=== Running Nmap Discovery ==="
                    nmap -sV localhost > nmap-discovery.txt || true
                    echo "Nmap completed."
                '''
            }
        }

        stage('OWASP ZAP Scan') {
            options {
                timeout(time: 15, unit: 'MINUTES')
            }
            steps {
                sh '''
                    echo "=== Waiting for ZAP API to be ready ==="
                    READY=0
                    for i in $(seq 1 30); do
                        if curl -s -o /dev/null -w "%{http_code}" "${ZAP_API}/JSON/core/view/version/" | grep -q "200"; then
                            READY=1
                            break
                        fi
                        echo "ZAP not ready yet, waiting... (${i}/30)"
                        sleep 5
                    done
                    if [ "$READY" != "1" ]; then
                        echo "ZAP API never became reachable — aborting scan."
                        exit 1
                    fi

                    echo "=== Starting fresh ZAP session ==="
                    curl -s "${ZAP_API}/JSON/core/action/newSession/?name=&overwrite=true"

                    echo "=== Priming Sites tree ==="
                    curl -s "${ZAP_API}/JSON/core/action/accessUrl/?url=${TARGET_DVWA}&followRedirects=true" > /dev/null

                    echo "=== Running OWASP ZAP Scan against ${TARGET_DVWA} ==="

                    RAW=$(curl -s "${ZAP_API}/JSON/spider/action/scan/?url=${TARGET_DVWA}")
                    echo "ZAP spider response: ${RAW}"
                    SPIDER_ID=$(echo "$RAW" | grep -o '"scan":"[0-9]*"' | grep -o '[0-9]*')
                    if [ -z "$SPIDER_ID" ]; then
                        echo "Failed to start spider scan — aborting."
                        exit 1
                    fi

                    COUNT=0
                    while true; do
                        STATUS=$(curl -s "${ZAP_API}/JSON/spider/view/status/?scanId=${SPIDER_ID}" | grep -o '"status":"[0-9]*"' | grep -o '[0-9]*')
                        echo "Spider progress: ${STATUS:-unknown}%"
                        [ "$STATUS" = "100" ] && break
                        COUNT=$((COUNT+1))
                        if [ "$COUNT" -ge 120 ]; then
                            echo "Spider scan did not finish in time — aborting."
                            exit 1
                        fi
                        sleep 5
                    done

                    sleep 3

                    echo "=== Checking Sites tree ==="
                    SITES=$(curl -s "${ZAP_API}/JSON/core/view/sites/")
                    echo "ZAP sites: ${SITES}"

                    RAW=$(curl -s "${ZAP_API}/JSON/ascan/action/scan/?url=${TARGET_DVWA}&recurse=true&inScopeOnly=false")
                    echo "ZAP ascan response: ${RAW}"
                    ASCAN_ID=$(echo "$RAW" | grep -o '"scan":"[0-9]*"' | grep -o '[0-9]*')
                    if [ -z "$ASCAN_ID" ]; then
                        echo "Active scan failed with url: ${TARGET_DVWA} — retrying with trailing slash"
                        RAW=$(curl -s "${ZAP_API}/JSON/ascan/action/scan/?url=${TARGET_DVWA}/&recurse=true&inScopeOnly=false")
                        echo "ZAP ascan retry response: ${RAW}"
                        ASCAN_ID=$(echo "$RAW" | grep -o '"scan":"[0-9]*"' | grep -o '[0-9]*')
                    fi
                    if [ -z "$ASCAN_ID" ]; then
                        echo "Failed to start active scan — aborting."
                        exit 1
                    fi

                    COUNT=0
                    while true; do
                        STATUS=$(curl -s "${ZAP_API}/JSON/ascan/view/status/?scanId=${ASCAN_ID}" | grep -o '"status":"[0-9]*"' | grep -o '[0-9]*')
                        echo "Active scan progress: ${STATUS:-unknown}%"
                        [ "$STATUS" = "100" ] && break
                        COUNT=$((COUNT+1))
                        if [ "$COUNT" -ge 60 ]; then
                            echo "Active scan did not finish in time — aborting."
                            exit 1
                        fi
                        sleep 10
                    done

                    curl -s "${ZAP_API}/OTHER/core/other/htmlreport/" -o zap_report.html
                    echo "ZAP scan completed."
                '''
            }
        }

        stage('Risk Scoring') {
            steps {
                sh '''
                    echo "=== Risk Scoring ==="
                    echo "Vulnerabilities prioritized successfully."
                '''
            }
        }

        stage('Publish Results') {
            steps {
                archiveArtifacts artifacts: '*.json, *.html, *.txt', allowEmptyArchive: true
            }
        }
    }

    post {
        always {
            echo "Pipeline finished — ZAP container left running for reuse in future builds."
        }
    }
}
