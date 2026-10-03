# Revisión independiente de anti-patrones — fase D

Se leyó el hub vigente del Cerebro y los contratos de implementation-plan,
software-compliance, integrations y durable-workers-scheduling. Los contadores
históricos del hub no sustituyen las fuentes actuales. Revisión estructurada
con code-review-structured; exclusivamente fixtures, datos SQLite aislados en
`.test-tmp-d-antipattern`, mocks y lectura de fuentes. Ningún destino real,
feed, instalación de herramientas o base de usuario fue utilizado.

## 🐛 BUGS

1. **P1 — autorización revocada ignorada por enriquecimientos activos, corregido.**
   **Ubicación:** `jobs.DurableQueue.submit_enrichment`, `worker._enrich` y
   `linux_inventory.inventory_scan`.
   **Descripción:** el productor almacenaba scan_id/kind/options; el worker
   invocaba el colector usando los hosts históricos vivos sin comprobar el
   alcance guardado vigente. El probe creó un alcance y escaneo completado,
   encoló Linux y después vació authorized_by o añadió el host a exclusions.
   En ambos casos alcanzó el mock de `linux_inventory.collect(192.0.2.10)`.
   El mock lanzó un sentinel antes de procesos o conexiones reales.
   **Fix aplicado:** capturar y revalidar el grant de alcance antes de las
   operaciones activas SSH/WinRM/MSF. La evaluación de evidencia histórica
   mediante feeds/análisis no requiere ejecución contra esos hosts.
   **Estado:** corregido y reverificado con siete casos independientes. Linux con
   autorización vacía, exclusión del host y alcance borrado falló antes del
   colector; Windows con autorización vacía también. Alcance guardado válido
   y ad-hoc válido alcanzaron el colector mock, detenido por sentinel. NVD
   sobre evidencia histórica siguió permitido y terminó done tras revocación.

## 🔒 SEGURIDAD

El P1 demostrado quedó corregido y reverificado. No se detectaron otros
problemas bloqueantes en el alcance revisado. El probe de
Syft acepta una fuente dentro de la raíz explícita del worker y rechaza una
ruta absoluta con traversal hacia fuera, una raíz hermana, registry sin
autorización de red y una referencia con credenciales. No inicia Syft.

Tres variantes de userinfo URI —literal, percent-encoded y protocol-relative—
se redactan. Una evidencia JSON con password, token anidado y URI elimina
los tres secretos fixture antes de persistencia/exportación.

## ⚡ RENDIMIENTO

No se encontró un anti-patrón bloqueante adicional. El único subprocess.run
identificado corresponde al sondeo Nmap --version con timeout de 15 segundos;
las ejecuciones de trabajos usan el runner compartido. La revisión no repite
la suite integral ni los probes de lease que pertenecen a otras puertas.

## 🔧 MEJORAS

La búsqueda shell=True/eval/exec no encontró ejecución dinámica de input.
Los imports dinámicos usan catálogos fijos; QUEUE de producción es DurableQueue.
El ThreadPoolExecutor permanece en la implementación heredada no utilizada por
la fachada global. Los executescript encontrados se usan en migraciones de
schemas, no en persistencia de resultados dentro del fence del worker.

## 📋 RESUMEN

- **Severidad global:** 🟢 Bajo, sin hallazgos bloqueantes pendientes.
- **Top 3 cambios prioritarios:**
  1. Mantener captura y revalidación de alcance vigente en operaciones activas.
  2. Conservar regresiones de revocación y exclusión antes del colector.
  3. Ejecutar la puerta integral sobre las fuentes reparadas.
- **Puntos positivos:** raíces explícitas del worker, redacción de evidencia,
  imports fijos y separación de encolado web/ejecución worker.

Veredicto: D01–D08 aceptables en el alcance de anti-patrones revisado, sujeto
a la puerta integral/distribución sobre estas fuentes finales. Los casos válidos
usaron un sentinel antes del colector real; su estado failed es intencionado
y demuestra que se admitió el grant sin ejecutar contra ningún destino.

