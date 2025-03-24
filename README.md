GIL mutex explaination
The GIL allows only one thread to execute Python code at a time, even if you have multiple threads running in parallel. 
This is critical to understand when dealing with operations like:
I/O-bound operations 
CPU-bound operations 

The goal here is to use time.time() to measure how long each section of the code takes to execute,
helping understand how thread parallelism behaves with Python’s GIL during network-based I/O operations.
