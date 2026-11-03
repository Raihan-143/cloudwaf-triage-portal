"""
utils/logger.py
Enterprise diagnostic logger with ANSI color-coding and zero emojis.
"""

from colorama import init, Fore, Style

init(autoreset=True)


class PortalLogger:
    @staticmethod
    def success(message: str) -> None:
        """Logs positive state or successful mitigation in green."""
        print(f"{Fore.GREEN}{Style.BRIGHT}[+]{Style.RESET_ALL} {message}")

    @staticmethod
    def alert(message: str) -> None:
        """Logs security anomaly, blocked attack, or high severity alert in red."""
        print(f"{Fore.RED}{Style.BRIGHT}[-]{Style.RESET_ALL} {message}")

    @staticmethod
    def info(message: str) -> None:
        """Logs standard telemetry or audit information in cyan."""
        print(f"{Fore.CYAN}{Style.BRIGHT}[*]{Style.RESET_ALL} {message}")

    @staticmethod
    def warning(message: str) -> None:
        """Logs potential vulnerability or warning in yellow."""
        print(f"{Fore.YELLOW}{Style.BRIGHT}[!]{Style.RESET_ALL} {message}")