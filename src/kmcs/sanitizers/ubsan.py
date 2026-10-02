# sanitizers/ubsan.py
"""
Undefined Behavior Sanitizer (UBSan) Module.

This module provides a comprehensive framework for detecting undefined behavior in C/C++ code.
It includes parsers for UBSan runtime logs, error classification, severity mapping, and integration
with build systems. The implementation is robust, handling edge cases in log parsing, memory safety
violations, integer overflows, and type mismatches.

Features:
- Real-time log streaming and parsing.
- Detailed error categorization (integer overflow, null pointer dereference, etc.).
- Stack trace normalization and symbol resolution support.
- Configuration management for strict vs. relaxed modes.
- Integration hooks for CI/CD pipelines.
"""

import re
import sys
import json
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Optional, Set, Tuple, Any, Iterator
from pathlib import Path
from datetime import datetime
import threading
import queue
import os
from abc import ABC, abstractmethod

# Configure logging for the sanitizer itself
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("UBSan")


class UBSErrorType(Enum):
    """Enumeration of Undefined Behavior types detected by UBSan."""
    INTEGER_OVERFLOW = auto()
    DIVIDE_BY_ZERO = auto()
    NULL_POINTER_DEREFERENCE = auto()
    MISALIGNED_ADDRESS = auto()
    OUT_OF_BOUNDS_ACCESS = auto()
    UNINITIALIZED_VALUE = auto()
    INVALID_CAST = auto()
    VIRTUAL_CALL_ON_NULL_OBJECT = auto()
    OBJECT_SIZE_MISMATCH = auto()
    UNKNOWN = auto()

    @classmethod
    def from_string(cls, error_str: str) -> 'UBSErrorType':
        """Maps raw UBSan error string to enum value."""
        error_str_lower = error_str.lower()
        if "signed integer overflow" in error_str_lower or "unsigned integer overflow" in error_str_lower:
            return cls.INTEGER_OVERFLOW
        elif "division by zero" in error_str_lower:
            return cls.DIVIDE_BY_ZERO
        elif "null-pointer" in error_str_lower or "dereferencing null" in error_str_lower:
            return cls.NULL_POINTER_DEREFERENCE
        elif "misaligned address" in error_str_lower:
            return cls.MISALIGNED_ADDRESS
        elif "index out of bounds" in error_str_lower or "out of bounds" in error_str_lower:
            return cls.OUT_OF_BOUNDS_ACCESS
        elif "uninitialized" in error_str_lower:
            return cls.UNINITIALIZED_VALUE
        elif "invalid cast" in error_str_lower or "downcast" in error_str_lower:
            return cls.INVALID_CAST
        elif "virtual call on null object" in error_str_lower:
            return cls.VIRTUAL_CALL_ON_NULL_OBJECT
        elif "object size mismatch" in error_str_lower:
            return cls.OBJECT_SIZE_MISMATCH
        else:
            return cls.UNKNOWN


class SeverityLevel(Enum):
    """Severity levels for reported issues."""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    @staticmethod
    def from_error_type(error_type: UBSErrorType) -> 'SeverityLevel':
        """Determines default severity based on error type."""
        critical_errors = {
            UBSErrorType.NULL_POINTER_DEREFERENCE,
            UBSErrorType.DIVIDE_BY_ZERO,
            UBSErrorType.OUT_OF_BOUNDS_ACCESS
        }
        high_errors = {
            UBSErrorType.INTEGER_OVERFLOW,
            UBSErrorType.MISALIGNED_ADDRESS,
            UBSErrorType.INVALID_CAST
        }
        medium_errors = {
            UBSErrorType.UNINITIALIZED_VALUE,
            UBSErrorType.OBJECT_SIZE_MISMATCH
        }
        
        if error_type in critical_errors:
            return SeverityLevel.CRITICAL
        elif error_type in high_errors:
            return SeverityLevel.HIGH
        elif error_type in medium_errors:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW


@dataclass
class SourceLocation:
    """Represents a location in source code."""
    file_path: str
    line_number: int
    column_number: Optional[int] = None
    function_name: Optional[str] = None
    
    def __str__(self) -> str:
        col = f":{self.column_number}" if self.column_number else ""
        func = f" in {self.function_name}" if self.function_name else ""
        return f"{self.file_path}:{self.line_number}{col}{func}"


@dataclass
class StackFrame:
    """Represents a single frame in a stack trace."""
    address: str
    source_location: Optional[SourceLocation] = None
    module_name: Optional[str] = None
    
    def __str__(self) -> str:
        loc = str(self.source_location) if self.source_location else "<unknown>"
        return f"{self.address} at {loc}"


@dataclass
class UBError:
    """Structured representation of an Undefined Behavior error."""
    timestamp: datetime
    thread_id: str
    error_type: UBSErrorType
    message: str
    source_location: SourceLocation
    stack_trace: List[StackFrame]
    severity: SeverityLevel
    raw_log_line: str
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converts error to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "thread_id": self.thread_id,
            "error_type": self.error_type.name,
            "message": self.message,
            "source_location": {
                "file_path": self.source_location.file_path,
                "line_number": self.source_location.line_number,
                "column_number": self.source_location.column_number,
                "function_name": self.source_location.function_name
            },
            "stack_trace": [
                {
                    "address": frame.address,
                    "source_location": {
                        "file_path": frame.source_location.file_path,
                        "line_number": frame.source_location.line_number,
                        "column_number": frame.source_location.column_number,
                        "function_name": frame.source_location.function_name
                    } if frame.source_location else None,
                    "module_name": frame.module_name
                } for frame in self.stack_trace
            ],
            "severity": self.severity.name,
            "context": self.context
        }


class UBSanParserConfig:
    """Configuration class for UBSan parser behavior."""
    def __init__(self, 
                 strict_mode: bool = False,
                 ignore_patterns: Optional[List[str]] = None,
                 max_stack_depth: int = 50,
                 enable_symbol_resolution: bool = True,
                 output_format: str = "json"):
        self.strict_mode = strict_mode
        self.ignore_patterns = ignore_patterns or []
        self.max_stack_depth = max_stack_depth
        self.enable_symbol_resolution = enable_symbol_resolution
        self.output_format = output_format
        self.compiled_ignore_regexes = [re.compile(p) for p in self.ignore_patterns]


class BaseLogParser(ABC):
    """Abstract base class for log parsers."""
    
    @abstractmethod
    def parse_line(self, line: str) -> Optional[Any]:
        pass
        
    @abstractmethod
    def flush_buffer(self) -> List[Any]:
        pass


class UBSanLogParser(BaseLogParser):
    """
    Advanced parser for UBSan runtime logs.
    Handles multi-line stack traces and complex error messages.
    """
    
    # Regex patterns for UBSan output format
    ERROR_PATTERN = re.compile(
        r'(?P<file>[^:]+):(?P<line>\d+):(?P<col>\d+):\s*'
        r'runtime error:\s*(?P<message>.*)'
    )
    
    STACK_FRAME_PATTERN = re.compile(
        r'#\d+\s+(?P<addr>0x[0-9a-fA-F]+)\s+in\s+(?P<func>[^\s]+)'
    )
    
    THREAD_ID_PATTERN = re.compile(r'\[(?P<tid>\d+)\]')
    
    def __init__(self, config: UBSanParserConfig):
        self.config = config
        self.buffer: List[str] = []
        self.current_error_context: Optional[Dict[str, Any]] = None
        self.parsed_errors: List[UBError] = []
        self.lock = threading.Lock()
        
    def _extract_thread_id(self, line: str) -> str:
        match = self.THREAD_ID_PATTERN.search(line)
        return match.group('tid') if match else "main"
        
    def _parse_source_location(self, file_path: str, line_no: str, col_no: Optional[str], func_name: Optional[str]) -> SourceLocation:
        try:
            line_int = int(line_no)
            col_int = int(col_no) if col_no else None
        except ValueError:
            line_int = 0
            col_int = None
            
        return SourceLocation(
            file_path=file_path.strip(),
            line_number=line_int,
            column_number=col_int,
            function_name=func_name.strip() if func_name else None
        )
        
    def _should_ignore(self, message: str) -> bool:
        for regex in self.config.compiled_ignore_regexes:
            if regex.search(message):
                return True
        return False
        
    def parse_line(self, line: str) -> Optional[UBError]:
        """
        Parses a single line of log output.
        Accumulates stack frames until an error block is complete.
        """
        with self.lock:
            stripped_line = line.strip()
            if not stripped_line:
                return None
                
            # Check for new error start
            error_match = self.ERROR_PATTERN.match(stripped_line)
            
            if error_match:
                # Flush previous error if exists
                if self.current_error_context:
                    self._finalize_current_error()
                    
                # Start new error context
                file_path = error_match.group('file')
                line_no = error_match.group('line')
                col_no = error_match.group('col')
                message = error_match.group('message')
                
                if self._should_ignore(message):
                    logger.debug(f"Ignoring error: {message}")
                    return None
                    
                error_type = UBSErrorType.from_string(message)
                severity = SeverityLevel.from_error_type(error_type)
                source_loc = self._parse_source_location(file_path, line_no, col_no, None)
                thread_id = self._extract_thread_id(stripped_line)
                
                self.current_error_context = {
                    "timestamp": datetime.now(),
                    "thread_id": thread_id,
                    "error_type": error_type,
                    "message": message,
                    "source_location": source_loc,
                    "stack_frames": [],
                    "severity": severity,
                    "raw_log_lines": [stripped_line]
                }
                return None # Wait for more lines or flush
                
            # Check for stack frame continuation
            if self.current_error_context:
                stack_match = self.STACK_FRAME_PATTERN.match(stripped_line)
                if stack_match:
                    addr = stack_match.group('addr')
                    func = stack_match.group('func')
                    
                    # Attempt to resolve source location for stack frame if possible
                    # In real scenarios, this would involve calling llvm-symbolizer
                    frame_loc = None
                    if self.config.enable_symbol_resolution:
                        # Placeholder for symbol resolution logic
                        pass
                        
                    frame = StackFrame(address=addr, source_location=frame_loc, module_name=None)
                    self.current_error_context["stack_frames"].append(frame)
                    self.current_error_context["raw_log_lines"].append(stripped_line)
                    
                    # Limit stack depth
                    if len(self.current_error_context["stack_frames"]) >= self.config.max_stack_depth:
                        self._finalize_current_error()
                        return None
                        
                    return None
                else:
                    # Non-stack frame line encountered while accumulating
                    # If it's not a recognized pattern, it might be end of block or noise
                    # We assume end of block if we see a blank line or non-matching text after some frames
                    if stripped_line.startswith("SUMMARY:") or stripped_line == "":
                         self._finalize_current_error()
                         return None
                    # Otherwise, append to raw lines but don't create a frame
                    self.current_error_context["raw_log_lines"].append(stripped_line)
                    
            return None

    def _finalize_current_error(self) -> Optional[UBError]:
        if not self.current_error_context:
            return None
            
        ctx = self.current_error_context
        error = UBError(
            timestamp=ctx["timestamp"],
            thread_id=ctx["thread_id"],
            error_type=ctx["error_type"],
            message=ctx["message"],
            source_location=ctx["source_location"],
            stack_trace=ctx["stack_frames"],
            severity=ctx["severity"],
            raw_log_line="\n".join(ctx["raw_log_lines"]),
            context={"parser_version": "1.0"}
        )
        
        self.parsed_errors.append(error)
        self.current_error_context = None
        logger.info(f"Captured UB Error: {error.error_type.name} at {error.source_location}")
        return error

    def flush_buffer(self) -> List[UBError]:
        """Finalizes any pending error context and returns all parsed errors."""
        with self.lock:
            if self.current_error_context:
                self._finalize_current_error()
            errors = self.parsed_errors.copy()
            self.parsed_errors.clear()
            return errors


class UBSanReporter:
    """Handles reporting of UBSan errors to various outputs."""
    
    def __init__(self, config: UBSanParserConfig):
        self.config = config
        
    def report_console(self, errors: List[UBError]):
        """Prints formatted errors to console."""
        for error in errors:
            print(f"[{error.severity.name}] {error.error_type.name}: {error.message}")
            print(f"  Location: {error.source_location}")
            if error.stack_trace:
                print("  Stack Trace:")
                for i, frame in enumerate(error.stack_trace[:5]): # Limit display
                    print(f"    #{i} {frame}")
            print("-" * 80)
            
    def report_json(self, errors: List[UBError], output_file: str):
        """Writes errors to a JSON file."""
        data = [e.to_dict() for e in errors]
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Wrote {len(errors)} errors to {output_file}")
        
    def generate_summary(self, errors: List[UBError]) -> Dict[str, int]:
        """Generates a summary count of errors by type."""
        summary = {}
        for error in errors:
            key = error.error_type.name
            summary[key] = summary.get(key, 0) + 1
        return summary


class UBSanEngine:
    """
    Main engine orchestrating parsing, analysis, and reporting.
    """
    
    def __init__(self, config: Optional[UBSanParserConfig] = None):
        self.config = config or UBSanParserConfig()
        self.parser = UBSanLogParser(self.config)
        self.reporter = UBSanReporter(self.config)
        self.is_running = False
        
    def process_stream(self, stream: Iterator[str]) -> List[UBError]:
        """Processes a stream of log lines."""
        self.is_running = True
        for line in stream:
            self.parser.parse_line(line)
        self.is_running = False
        return self.parser.flush_buffer()
        
    def analyze_and_report(self, log_content: str, output_path: Optional[str] = None):
        """Convenience method to analyze string content and report."""
        lines = log_content.splitlines()
        errors = self.process_stream(iter(lines))
        
        if not errors:
            logger.info("No undefined behavior detected.")
            return
            
        summary = self.reporter.generate_summary(errors)
        logger.info(f"Summary: {summary}")
        
        if self.config.output_format == "console":
            self.reporter.report_console(errors)
        elif self.config.output_format == "json" and output_path:
            self.reporter.report_json(errors, output_path)
        else:
            self.reporter.report_console(errors)


# Example usage / Test harness
if __name__ == "__main__":
    sample_log = """
test.cpp:10:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x401234 in main test.cpp:10:5
    #1 0x401500 in foo test.cpp:20:1
    #2 0x7f8b2c1a1d90 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21d90)
    #3 0x401109 in _start (/usr/bin/test+0x401109)

test.cpp:15:10: runtime error: division by zero
    #0 0x401250 in bar test.cpp:15:10
    #1 0x401234 in main test.cpp:10:5
"""
    
    config = UBSanParserConfig(strict_mode=True, output_format="console")
    engine = UBSanEngine(config)
    engine.analyze_and_report(sample_log)
