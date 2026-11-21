"""sentinel — agente de evaluación de seguridad con controles verificables.

Capacidades implementadas: descubrimiento (local y TCP connect), evaluación de
configuración, correlación de avisos por versión con CVSS v3.1 propio, análisis
de escalamiento de privilegios e informes con evidencia verificable.

Capacidades deliberadamente ausentes: explotación, ataques de credenciales y
validación activa de escalamiento (ver docs/DECISIONS.md, ADR-002/005/006).
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
