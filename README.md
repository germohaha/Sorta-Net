GIL mutex explaination
The GIL allows only one thread to execute Python code at a time, even if you have multiple threads running in parallel. 
This is critical to understand when dealing with operations like:
I/O-bound operations (network requests, file I/O, database access).
CPU-bound operations (computational tasks, algorithm processing).

The goal here is to use time.time() to measure how long each section of the code takes to execute,
helping you understand how parallelism behaves with Python’s GIL during network-based I/O operations.
