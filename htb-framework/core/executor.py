"""
core/executor.py
Parallel execution engine.

Menggunakan ThreadPoolExecutor karena workload kita I/O-bound:
- subprocess (network calls, file I/O)
- nunggu response dari target

Threading di Python ada GIL, tapi GIL DILEPAS saat thread blocking di I/O,
jadi efektif paralel untuk use case ini.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Callable, Any
from core import logger


class ParallelExecutor:
    """
    Wrapper buat menjalankan banyak task paralel dengan progress tracking.
    
    Pattern: submit tasks → wait → collect results
    """
    
    def __init__(self, max_workers: int = 5):
        """
        Args:
            max_workers: Jumlah thread maksimum yang jalan bersamaan.
                         Untuk HTB, 5 itu sweet spot:
                         - Cukup paralel buat speedup
                         - Tidak overwhelm target (rate limit, IDS)
                         - Tidak overload Kali VM kamu
        """
        self.max_workers = max_workers
        self.tasks = []
    
    def add_task(self, name: str, func: Callable, *args, **kwargs):
        """
        Daftarkan task untuk dieksekusi nanti.
        
        Args:
            name: Label untuk logging (misal "Gobuster_80").
            func: Function yang mau dipanggil.
            *args, **kwargs: Argumen untuk function tersebut.
        """
        self.tasks.append({
            "name": name,
            "func": func,
            "args": args,
            "kwargs": kwargs,
        })
    
    def run_all(self) -> dict[str, Any]:
        """
        Jalankan semua task paralel, tunggu semua selesai.
        
        Returns:
            dict mapping task_name -> result (atau None kalau gagal)
        """
        if not self.tasks:
            logger.warn("Tidak ada task untuk dijalankan")
            return {}
        
        logger.info(f"Menjalankan {len(self.tasks)} task paralel "
                    f"(max {self.max_workers} concurrent)...")
        
        results = {}
        future_to_name = {}
        
        # ThreadPoolExecutor sebagai context manager → otomatis cleanup
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit semua task
            for task in self.tasks:
                future = executor.submit(task["func"], *task["args"], **task["kwargs"])
                future_to_name[future] = task["name"]
            
            # as_completed: yield future yang sudah selesai (urutan tidak deterministik)
            # Ini lebih efisien daripada .result() berurutan karena kita
            # langsung tahu mana yang selesai duluan
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    result = future.result(timeout=1)
                    results[name] = result
                    logger.success(f"[DONE] {name}")
                except Exception as e:
                    logger.error(f"[FAIL] {name}: {e}")
                    results[name] = None
        
        # Reset task list agar instance bisa dipakai ulang
        self.tasks = []
        return results
    
    def run_background(self, name: str, func: Callable, *args, **kwargs) -> Future:
        """
        Submit SATU task ke background, tidak block main thread.
        
        Pattern berbeda dari run_all: ini "fire and check later".
        Berguna untuk full port scan yang jalan paralel dengan workflow utama.
        
        Returns:
            Future object — bisa di-poll dengan .done() atau di-tunggu dengan .result()
        """
        # Buat executor sendiri yang tidak di-shutdown saat function return
        # Caller bertanggung jawab handle cleanup
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=name)
        future = executor.submit(func, *args, **kwargs)
        # Attach metadata agar bisa di-track
        future._executor = executor
        future._name = name
        logger.info(f"[BACKGROUND] {name} dimulai")
        return future
