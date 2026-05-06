"""
API models for VexSym verification service.

Defines request and response schemas using Pydantic.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class Language(str, Enum):
    """Supported programming languages."""
    C = "c"
    CPP = "cpp"


class VerifyRequest(BaseModel):
    """
    Request model for verification endpoint.
    """
    decompiled_code: str = Field(
        ...,
        description="The decompiled C/C++ source code to verify",
        min_length=1
    )
    
    language: Language = Field(
        default=Language.C,
        description="Programming language (c or cpp)"
    )
    
    function_name: str = Field(
        default="main",
        description="Name of the function to verify"
    )
    
    num_args: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Number of function arguments"
    )
    
    arg_types: Optional[List[str]] = Field(
        default=None,
        description="Argument types (e.g., ['int64', 'ptr', 'int32'])"
    )
    
    loop_bound: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum loop iterations"
    )
    
    timeout: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="Execution timeout in seconds"
    )
    
    compare_memory: bool = Field(
        default=False,
        description="Whether to compare memory side effects"
    )
    
    compiler_flags: List[str] = Field(
        default_factory=list,
        description="Additional compiler flags"
    )


class InputValue(BaseModel):
    """Concrete input value that triggers divergence."""
    name: str
    value: int
    hex: str
    signed: Optional[int] = None


class OutputValue(BaseModel):
    """Output value from execution."""
    value: Any
    hex: str


class Divergence(BaseModel):
    """Details of a detected divergence."""
    type: str = Field(description="Type of divergence (e.g., return_value_mismatch)")
    inputs: List[InputValue] = Field(description="Concrete input values")
    orig_output: OutputValue = Field(description="Output from original binary")
    dec_output: OutputValue = Field(description="Output from decompiled binary")
    execution_traces: Optional[Dict[str, List[str]]] = Field(
        default=None,
        description="Execution traces for debugging"
    )


class VerificationStatistics(BaseModel):
    """Statistics about the verification process."""
    states_orig: int
    states_dec: int
    comparisons_attempted: int
    path_pairs_compatible: int


class VerifyResponse(BaseModel):
    """
    Response model for verification endpoint.
    """
    status: str = Field(
        description="Status: 'equivalent', 'different', 'error', 'timeout'"
    )
    
    message: Optional[str] = Field(
        default=None,
        description="Human-readable message"
    )
    
    equivalent: Optional[bool] = Field(
        default=None,
        description="Whether programs are equivalent"
    )
    
    divergences: Optional[List[Divergence]] = Field(
        default=None,
        description="List of divergences found"
    )
    
    statistics: Optional[VerificationStatistics] = Field(
        default=None,
        description="Verification statistics"
    )
    
    compilation_error: Optional[str] = Field(
        default=None,
        description="Compilation error details if applicable"
    )


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    compilers: Dict[str, Any]


class FunctionInfo(BaseModel):
    """Information about a function in a binary."""
    name: str
    address: str
    size: Optional[int] = None


class BinaryInfoResponse(BaseModel):
    """Response with binary metadata."""
    filename: str
    architecture: str
    bits: int
    entry_point: str
    functions: List[FunctionInfo]
