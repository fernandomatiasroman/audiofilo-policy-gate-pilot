"""Cambio inocuo para disparar el circuito del revisor independiente.

Sólo existe para que un PR de prueba active `reviewer-analysis` y, por
`workflow_run`, `reviewer-publish` en modo DRY_RUN. No toca `src/` ni el
comportamiento de ninguna otra prueba.
"""

import unittest


class ReviewerAuthTriggerTests(unittest.TestCase):
    def test_marcador_presente(self):
        self.assertEqual("reviewer-auth-trigger-01", "reviewer-auth-trigger-01")


if __name__ == "__main__":
    unittest.main()
