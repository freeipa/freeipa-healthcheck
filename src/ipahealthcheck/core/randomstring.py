import random
import string


def generate_random_str(length=16):
    base = string.ascii_letters + string.digits
    return ''.join(random.choice(base) for i in range(length))
