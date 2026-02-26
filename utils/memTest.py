import tracemalloc
import time


class ProductA:
    def __init__(self):
        self.name = "ProductA"

class ProductB:
    def __init__(self):
        self.name = "ProductB"

class AbstractFactory:
    def create_product(self, product_type):
        if product_type == "A":
            return ProductA()
        elif product_type == "B":
            return ProductB()
        else:
            raise ValueError("Unknown product type")
        
def test_memory_usage():
    factory = AbstractFactory()
    count = 0

    tracemalloc.start()

    snapsot_before = tracemalloc.take_snapshot()
    for _ in range(10000):
        product_a = factory.create_product("A")
        product_b = factory.create_product("B")
        count = count + 1
        del product_a, product_b

    time.sleep(1)

    snapsot_after = tracemalloc.take_snapshot()

    top_stats = snapsot_after.compare_to(snapsot_before, 'lineno')

    print("Memory usage differences: ")
    for stat in top_stats[:10]:
        print(stat)

    tracemalloc.stop()
    print(f"number of iterations {count}")
if __name__ == "__main__":
    test_memory_usage()