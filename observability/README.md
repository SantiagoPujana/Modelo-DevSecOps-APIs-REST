# Observabilidad local con Docker, Prometheus y Grafana

Este archivo README.md explica cómo probar localmente la fase de observabilidad del proyecto usando una red Docker compartida entre la API `api-auth` y el stack de monitoreo.

---

## Prerrequisitos

Asegúrate de tener instalado:

- Docker
- Docker Compose
- Python y dependencias de la API ya configuradas en `api-auth`
- La instrumentación de Prometheus agregada en `main.py`
- La dependencia `prometheus-fastapi-instrumentator` agregada en `requirements.txt`

---

## Estructura esperada

La carpeta `observability` debería quedar al menos así:

```text
observability/
├─ docker-compose.yml
├─ README.md
├─ prometheus/
│  ├─ prometheus.yml
│  └─ alerts.yml
├─ grafana/
│  ├─ provisioning/
│  │  ├─ datasources/
│  │  │  └─ datasource.yml
│  │  └─ dashboards/
│  │     └─ dashboards.yml
│  └─ dashboards/
│     └─ api-observability.json
```

---

## Paso 1. Crear la red Docker compartida

Ejecuta este comando una sola vez:

```bash
docker network create devsecops-net
```

Si la red ya existe, Docker mostrará un mensaje y no pasa nada.

---

## Paso 2. Levantar la API

Desde la carpeta `api-auth` ejecuta:

```bash
cd api-auth
docker compose up -d --build
```

Esto debería dejar la API disponible en:

```text
http://localhost:8000
```

---

## Paso 3. Verificar que la API expone métricas

Antes de levantar Prometheus, valida que el endpoint `/metrics` exista:

```bash
curl http://localhost:8000/metrics
```

Si todo está bien, deberías ver métricas en formato Prometheus.

También puedes probar:

```bash
curl http://localhost:8000
curl http://localhost:8000/docs
curl http://localhost:8000/openapi.json
curl http://localhost:8000/user?username=admin
curl http://localhost:8000/hash?password=test123
curl http://localhost:8000/read?path=/etc/hosts
curl http://localhost:8000/metrics
```

---

## Paso 4. Levantar el stack de observabilidad

Desde la carpeta `observability` ejecuta:

```bash
cd ../observability
docker compose up -d
```

Esto levantará:

- Prometheus
- Grafana
- Node Exporter

---

## Paso 5. Verificar los contenedores

Puedes revisar que todo esté arriba con:

```bash
docker ps -a
```

Deberías ver contenedores como:

- `api-auth`
- `prometheus`
- `grafana`
- `node-exporter`

---

## Paso 6. Validar Prometheus

Abre:

```text
http://localhost:9090/targets
```

Revisa que los targets aparezcan en estado **UP**, especialmente:

- `prometheus`
- `node-exporter`
- `api-auth`

Si `api-auth` no aparece en `UP`, revisa:

- que la API esté corriendo
- que `/metrics` responda
- que ambos compose estén conectados a la red `devsecops-net`

---

## Paso 7. Validar Grafana

Abre:

```text
http://localhost:3000
```

Credenciales por defecto:

- Usuario: `admin`
- Contraseña: `admin123`

Una vez dentro, verifica:

- que el datasource de Prometheus exista
- que el dashboard se haya cargado
- que veas paneles de CPU, memoria y estado de targets

---

## Paso 8. Validar alertas mínimas

Prometheus tiene reglas básicas como:

- target caído
- uso alto de CPU
- uso alto de memoria

Puedes revisarlas en:

```text
http://localhost:9090/alerts
```

---

## Paso 9. Detener el entorno

Para detener la observabilidad:

```bash
cd observability
docker compose down
```

Para detener la API:

```bash
cd ../api-auth
docker compose down
```

---

## Problemas comunes

### 1. `api-auth` no aparece como `UP` en Prometheus
Verifica que en `observability/prometheus/prometheus.yml` exista:

```yaml
- job_name: api-auth
  metrics_path: /metrics
  static_configs:
    - targets: ["api-auth:8000"]
```

Y que el servicio `api-auth` esté conectado a la red `devsecops-net`.

### 2. Grafana no muestra datos
Verifica:

- que Prometheus esté `UP`
- que el datasource apunte a `http://prometheus:9090`
- que los targets estén en `UP`

### 3. `/metrics` no responde
Verifica en `main.py` que exista la instrumentación:

```python
from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)
```

Y en `requirements.txt`:

```text
prometheus-fastapi-instrumentator
```

---

## Resultado esperado

Al finalizar esta prueba local deberías tener:

- la API instrumentada con métricas
- Prometheus recolectando métricas de la API
- Grafana mostrando dashboards
- reglas de alerta mínimas funcionando
- una base funcional para la fase de Monitoring del pipeline DevSecOps

---

## Nota

Esta validación es local, pensada para pruebas del trabajo de grado. Más adelante se puede migrar a una infraestructura cloud si se requiere, pero por ahora esta implementación permite demostrar completamente la fase de monitoreo y alertamiento.
