# Generador de tráfico para `api-auth`

Este archivo README.md explica cómo usar el script `generate_api_traffic.py` para generar tráfico HTTP sobre la API `api-auth`, con el fin de:

- poblar métricas en Prometheus
- visualizar actividad en Grafana
- validar respuestas básicas de la API
- simular tráfico controlado sobre endpoints exitosos y fallidos

---

## Requisitos previos

Antes de ejecutar el script, asegúrate de que:

1. La API `api-auth` esté levantada localmente.
2. El endpoint `/metrics` responda correctamente.
3. Prometheus y Grafana estén corriendo.
4. Tengas instalada la dependencia `requests` en tu entorno Python, si no la tienes entonces ejecuta:

```bash
python3 -m pip install -r tests/requirements.txt
```

Ejemplo para validar la API:

```bash
curl http://localhost:8000/
curl http://localhost:8000/metrics
```

---

## Ejecución básica

Desde la raíz del proyecto:

```bash
python3 tests/generate_api_traffic.py
```

Esto ejecuta una configuración por defecto:

- `base-url`: `http://localhost:8000`
- `rounds`: `10`
- `sleep`: `0.5`
- solo endpoints exitosos

---

## Ver ayuda

El script soporta `--help` automáticamente.

```bash
python3 tests/generate_api_traffic.py --help
```

Eso mostrará todos los parámetros disponibles.

---

## Parámetros disponibles

### `--base-url`
Define la URL base de la API.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --base-url http://localhost:8000
```

---

### `--rounds`
Cantidad de rondas completas de tráfico.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --rounds 20
```

---

### `--sleep`
Tiempo de espera entre llamadas, en segundos.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --sleep 0.2
```

---

### `--timeout`
Timeout por request, en segundos.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --timeout 5
```

---

### `--include-failures`
Incluye endpoints que tienden a producir errores o respuestas fallidas, útiles para poblar métricas de errores HTTP.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --include-failures
```

---

### `--only`
Permite ejecutar solo ciertos endpoints por nombre.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --only root docs metrics user_ok hash
```

---

### `--random-order`
Mezcla aleatoriamente el orden de los endpoints en cada ronda.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --random-order
```

---

### `--list-endpoints`
Lista los endpoints disponibles y termina la ejecución.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --list-endpoints
```

---

### `--stop-on-error`
Detiene la ejecución si ocurre un error de conexión.

Ejemplo:

```bash
python3 tests/generate_api_traffic.py --stop-on-error
```

---

## Ejemplos de uso

### 1. Ejecución por defecto

```bash
python3 tests/generate_api_traffic.py
```

---

### 2. Más rondas y menos espera

```bash
python3 tests/generate_api_traffic.py --rounds 30 --sleep 0.1 --random-order
```

---

### 3. Incluir endpoints que generen errores

```bash
python3 tests/generate_api_traffic.py --include-failures --rounds 20 --sleep 0.2
```

---

### 4. Ejecutar solo endpoints específicos

```bash
python3 tests/generate_api_traffic.py --only root openapi metrics user_ok hash
```

---

### 5. Ver endpoints disponibles

```bash
python3 tests/generate_api_traffic.py --list-endpoints
```

---

## Endpoints contemplados por el script

Dependiendo de los parámetros, el script puede generar tráfico sobre:

- `/`
- `/docs`
- `/openapi.json`
- `/metrics`
- `/user`
- `/hash`
- `/read`
- `/exec`
- `/fetch`

También puede incluir casos exitosos y fallidos para enriquecer las métricas.

---

## Qué esperar después de ejecutarlo

Al terminar, el script muestra:

- total de llamadas realizadas
- tiempo promedio
- distribución por códigos de respuesta
- cantidad de llamadas por endpoint

Después de ejecutarlo, revisa:

### Prometheus
```text
http://localhost:9090
http://localhost:9090/targets
http://localhost:9090/alerts
```

### Grafana
```text
http://localhost:3000
```

---

## Casos de uso dentro del proyecto

Este script sirve para:

- generar tráfico de prueba para Prometheus
- poblar dashboards en Grafana
- observar latencia y volumen de requests
- provocar respuestas 4xx/5xx de forma controlada
- demostrar la fase de monitoreo del modelo DevSecOps

---

## Recomendación

Si quieres poblar mejor el dashboard de Grafana, ejecuta una carga como esta:

```bash
python3 tests/generate_api_traffic.py --include-failures --rounds 25 --sleep 0.1 --random-order
```

Eso suele generar suficiente tráfico para ver:

- requests por segundo
- requests por status
- errores 4xx/5xx
- latencia promedio
- actividad por endpoint
