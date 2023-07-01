import math
from random import randint


def create_nonce():
    return randint(10 ** 3, 10 ** 6)


def convert_nonce(nonce: int):
    return (nonce + 2) ** 3


def validate_nonce(nonce, converted_nonce):
    return converted_nonce == convert_nonce(nonce)