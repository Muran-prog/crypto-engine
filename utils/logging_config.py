"""
Logging configuration utilities for the cryptographic engine.

This module provides centralized logging setup and configuration.

Author: Muran-prog
License: MIT
Version: 2.0
"""

import logging


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configure logging for the crypto engine.
    
    Args:
        level: Logging level (default: INFO)
    """
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


# Configure default logging
setup_logging()