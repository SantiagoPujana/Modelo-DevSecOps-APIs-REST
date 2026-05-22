# Modelo de Monitoreo y Seguimiento de APIs REST para DevSecOps

Repositorio de soporte para la implementación y validación de un modelo de monitoreo y seguimiento de APIs REST orientado a prácticas DevSecOps. El proyecto integra controles de seguridad en distintas fases del ciclo de vida: análisis estático, análisis de dependencias, análisis dinámico, validación de políticas de despliegue y monitoreo/observabilidad.

## Estructura del repositorio

- `api-auth/`: API de ejemplo vulnerable usada como laboratorio para pruebas de SAST, SCA, DAST y monitoreo.
- `.github/workflows/`: workflows de GitHub Actions para las fases del pipeline DevSecOps.
- `security/`: políticas, modelos y evidencias relacionadas con seguridad.
  - `security/policies/`: políticas como código para validaciones de despliegue.
  - `security/evidence/`: evidencias generadas por herramientas de seguridad cuando aplica.
- `observability/`: configuración de observabilidad con Prometheus, Grafana y Node Exporter.
- `infra/`: artefactos de infraestructura y documentación asociada.
- `tests/`: scripts y recursos de prueba, incluyendo generación de tráfico hacia la API para poblar métricas y validar observabilidad.
- `pipelines/`: documentación o artefactos complementarios del pipeline, si aplica.

## Fases implementadas del modelo

### Fase 1 - SAST
Análisis estático de código con SonarQube/SonarCloud sobre la API de ejemplo.

### Fase 2 - SCA
Escaneo de dependencias y librerías con:
- Trivy
- OWASP Dependency-Check

### Fase 3 - DAST
Escaneo dinámico de la API con OWASP ZAP.

### Fase 4 - Security Gate
Consolidación de resultados de seguridad para validar si el flujo puede continuar.

### Fase 5 - Deploy Policy Check
Validación de políticas de despliegue mediante OPA/Conftest, con reglas orientadas a control de acceso, autorización y entorno objetivo.

### Fase 6 - Monitoring Check
Validación automatizada del entorno de observabilidad con:
- API instrumentada con métricas
- Prometheus
- Grafana
- Node Exporter

### Fase 7 - Final Pipeline Gate
Validación final del flujo posterior a seguridad, despliegue y monitoreo.

## Observabilidad

La carpeta `observability/` contiene la configuración base para levantar localmente un entorno de monitoreo con Docker Compose, incluyendo:

- Prometheus
- Grafana
- Node Exporter

La API `api-auth` expone el endpoint `/metrics`, lo que permite su integración con Prometheus y la visualización en dashboards de Grafana.

## Pruebas y tráfico sintético

La carpeta `tests/` incluye scripts para generar tráfico sobre la API, con el fin de:

- poblar métricas en Prometheus
- visualizar actividad en Grafana
- observar comportamiento por endpoint
- simular respuestas exitosas y fallidas
