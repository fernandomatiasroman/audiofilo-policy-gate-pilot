import unittest
from src.calculator import multiply, subtract


class CalculatorTests(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(multiply(3, 4), 12)

    def test_negative(self):
        self.assertEqual(multiply(-3, 4), -12)

    def test_zero(self):
        self.assertEqual(multiply(0, 7), 0)

    def test_decimal(self):
        self.assertAlmostEqual(multiply(0.1, 0.2), 0.02)


class SubtractTests(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(subtract(10, 4), 6)

    def test_negative(self):
        self.assertEqual(subtract(4, 10), -6)

    def test_zero(self):
        self.assertEqual(subtract(5, 5), 0)


if __name__ == "__main__":
    unittest.main()
