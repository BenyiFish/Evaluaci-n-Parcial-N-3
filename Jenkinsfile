pipeline {
    agent any

    environment {
        IMAGE = "securedev-app:${env.BUILD_NUMBER}"
    }

    stages {
        stage('Construcción') {
            steps {
                sh 'docker build -t $IMAGE .'
            }
        }

        stage('Pruebas') {
            steps {
                sh '''
                docker run -d --name zap-target-${BUILD_NUMBER} -p 8081:8000 $IMAGE
                sleep 5
                docker run --rm -v "${PWD}:/zap/wrk:rw" zaproxy/zap-stable \
                    zap-baseline.py -t http://host.docker.internal:8081 -r zap-before.html || true
                docker rm -f zap-target-${BUILD_NUMBER} || true
                '''
            }
        }

        stage('Despliegue') {
            steps {
                sh 'docker compose up -d --build'
                sh 'curl -sf http://host.docker.internal:8000/health'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '**/*.html', allowEmptyArchive: true
        }
    }
}
