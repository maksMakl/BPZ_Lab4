import hmac
import os
import time


# ВРАЗЛИВО: оператор == завершується на першому відмінному байті (витік через часовий канал)
def verify_tag_v1(expected: bytes, provided: bytes) -> bool:
    return expected == provided


# БЕЗПЕЧНО: порівняння за сталий час незалежно від позиції розбіжності
def verify_tag_v2(expected: bytes, provided: bytes) -> bool:
    return hmac.compare_digest(expected, provided)


if __name__ == "__main__":
    expected_tag = os.urandom(1024)
    wrong_first_byte = bytes([expected_tag[0] ^ 0xFF]) + expected_tag[1:]
    wrong_last_byte = expected_tag[:-1] + bytes([expected_tag[-1] ^ 0xFF])

    iterations = 10_000_000

    # Вимірювання для вразливого ==
    t0 = time.perf_counter()
    for _ in range(iterations):
        verify_tag_v1(expected_tag, wrong_first_byte)
    t_v1_first = (time.perf_counter() - t0) * 1e6 / iterations

    t0 = time.perf_counter()
    for _ in range(iterations):
        verify_tag_v1(expected_tag, wrong_last_byte)
    t_v1_last = (time.perf_counter() - t0) * 1e6 / iterations

    # Вимірювання для безпечного hmac.compare_digest
    t0 = time.perf_counter()
    for _ in range(iterations):
        verify_tag_v2(expected_tag, wrong_first_byte)
    t_v2_first = (time.perf_counter() - t0) * 1e6 / iterations

    t0 = time.perf_counter()
    for _ in range(iterations):
        verify_tag_v2(expected_tag, wrong_last_byte)
    t_v2_last = (time.perf_counter() - t0) * 1e6 / iterations

    print("=== Порівняння оператором == (# ВРАЗЛИВО) ===")
    print(f"Розбіжність у першому байті:     {t_v1_first:.2f} мікросекунд")
    print(f"Розбіжність в останньому байті:  {t_v1_last:.2f} мікросекунд (різниця у {t_v1_last / t_v1_first:.1f}x)")

    print("\n=== Порівняння через hmac.compare_digest (# БЕЗПЕЧНО) ===")
    print(f"Розбіжність у першому байті:     {t_v2_first:.2f} мікросекунд")
    print(f"Розбіжність в останньому байті:  {t_v2_last:.2f} мікросекунд (різниця у {t_v2_last / t_v2_first:.2f}x)")