from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed


# 任务池
def quicksliver(func,number_process):

    with ThreadPoolExecutor(max_workers = number_process) as executor:
        futures = [executor.submit(func) for count in range(number_process)]

