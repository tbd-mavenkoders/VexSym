"""
VexSym FastAPI Server

RESTful API for bounded relational symbolic execution verification.

Endpoints:
- POST /verify: Verify decompilation equivalence
- GET /health: Health check
- POST /analyze-binary: Get binary information
"""

import os
import logging
import tempfile
import asyncio
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models import (
    VerifyRequest,
    VerifyResponse,
    HealthResponse,
    BinaryInfoResponse,
    FunctionInfo,
    VerificationStatistics,
    Divergence,
    Language,
    InputValue,
    OutputValue,
)

from vexsym.core import (
    compile_source,
    load_projects,
    create_entangled_states,
    setup_cpp_state,
    run_bounded_execution,
    compare_results,
)

from vexsym.core.compiler import verify_compiler_availability, CompilationError
from vexsym.core.loader import get_project_info, list_all_functions, ProjectLoadError
from vexsym.core.entangler import EntanglementError
from vexsym.core.executor import ExecutionError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="VexSym API",
    description="Bounded Relational Symbolic Execution for Decompilation Verification",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import version
from vexsym import __version__


@app.get("/", tags=["General"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "VexSym API",
        "version": __version__,
        "description": "Decompilation verification using bounded relational symbolic execution",
        "docs": "/docs",
        "endpoints": {
            "verify": "POST /verify",
            "health": "GET /health",
            "analyze_binary": "POST /analyze-binary",
        }
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
async def health_check():
    """
    Health check endpoint.
    
    Returns system status and compiler availability.
    """
    compiler_info = verify_compiler_availability()
    
    return HealthResponse(
        status="healthy",
        version=__version__,
        compilers=compiler_info
    )


@app.post("/verify", response_model=VerifyResponse, tags=["Verification"])
async def verify_decompilation(
    decompiled_code: str = Form(..., description="Decompiled C/C++ source code"),
    language: str = Form(default="c", description="Programming language (c or cpp)"),
    function_name: str = Form(default="main", description="Function name to verify"),
    num_args: int = Form(default=3, ge=0, le=10, description="Number of arguments"),
    loop_bound: int = Form(default=5, ge=1, le=20, description="Maximum loop iterations"),
    timeout: int = Form(default=300, ge=10, le=3600, description="Timeout in seconds"),
    original_binary: UploadFile = File(..., description="Original binary file"),
    background_tasks: BackgroundTasks = None,
):
    """
    Verify semantic equivalence between original binary and decompiled code.
    
    This endpoint:
    1. Compiles the decompiled source code
    2. Loads both binaries into angr
    3. Creates entangled symbolic states
    4. Runs bounded symbolic execution
    5. Compares results to find discrepancies
    
    Returns:
        VerifyResponse with equivalence status and any divergences found
    """
    # Create request object from form fields
    request = VerifyRequest(
        decompiled_code=decompiled_code,
        language=Language(language),
        function_name=function_name,
        num_args=num_args,
        loop_bound=loop_bound,
        timeout=timeout
    )
    logger.info(f"Received verification request for function '{request.function_name}'")
    logger.info(f"Language: {request.language}, Loop bound: {request.loop_bound}")
    
    orig_path = None
    dec_bin_path = None
    
    try:
        # 1. Save uploaded binary to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            content = await original_binary.read()
            tmp.write(content)
            orig_path = tmp.name
        
        logger.info(f"Saved original binary to: {orig_path}")
        
        # 2. Compile decompiled source
        try:
            dec_bin_path = compile_source(
                request.decompiled_code,
                is_cpp=(request.language.value == "cpp"),
                extra_flags=request.compiler_flags
            )
            logger.info(f"Compiled decompiled code to: {dec_bin_path}")
        
        except CompilationError as e:
            logger.error(f"Compilation failed: {e}")
            return VerifyResponse(
                status="error",
                message="Compilation failed",
                compilation_error=str(e)
            )
        
        # 3. Load both binaries into angr
        try:
            proj_orig, proj_dec = load_projects(orig_path, dec_bin_path)
            logger.info("Successfully loaded both binaries")
        
        except ProjectLoadError as e:
            logger.error(f"Failed to load projects: {e}")
            raise HTTPException(status_code=400, detail=f"Binary loading failed: {str(e)}")
        
        # 4. Create entangled states
        try:
            state_orig, state_dec, symbolic_args = create_entangled_states(
                proj_orig,
                proj_dec,
                request.function_name,
                arg_types=request.arg_types,
                num_args=request.num_args
            )
            logger.info("Created entangled states")
            
            # Handle C++ if needed
            if request.language.value == "cpp":
                setup_cpp_state(state_orig, is_x64=(proj_orig.arch.bits == 64))
                setup_cpp_state(state_dec, is_x64=(proj_dec.arch.bits == 64))
                logger.info("Configured C++ states")
        
        except EntanglementError as e:
            logger.error(f"State entanglement failed: {e}")
            raise HTTPException(status_code=400, detail=f"State setup failed: {str(e)}")
        
        # 5. Run bounded execution with timeout
        try:
            # Run both executions
            logger.info("Starting symbolic execution on original binary")
            states_orig = await asyncio.wait_for(
                asyncio.to_thread(
                    run_bounded_execution,
                    proj_orig,
                    state_orig,
                    loop_bound=request.loop_bound,
                    timeout_seconds=request.timeout
                ),
                timeout=request.timeout + 10  # Extra buffer
            )
            
            logger.info("Starting symbolic execution on decompiled binary")
            states_dec = await asyncio.wait_for(
                asyncio.to_thread(
                    run_bounded_execution,
                    proj_dec,
                    state_dec,
                    loop_bound=request.loop_bound,
                    timeout_seconds=request.timeout
                ),
                timeout=request.timeout + 10
            )
            
            logger.info(f"Execution complete. States: orig={len(states_orig)}, dec={len(states_dec)}")
        
        except asyncio.TimeoutError:
            logger.error("Execution timed out")
            return VerifyResponse(
                status="timeout",
                message=f"Execution exceeded timeout of {request.timeout} seconds"
            )
        
        except ExecutionError as e:
            logger.error(f"Execution failed: {e}")
            raise HTTPException(status_code=500, detail=f"Symbolic execution failed: {str(e)}")
        
        # 6. Compare results
        logger.info("Comparing results")
        comparison_result = await asyncio.to_thread(
            compare_results,
            states_orig,
            states_dec,
            symbolic_args,
            compare_memory=request.compare_memory
        )
        
        # 7. Format response
        if comparison_result.equivalent:
            return VerifyResponse(
                status="equivalent",
                message="No divergence found within execution bounds",
                equivalent=True,
                statistics=VerificationStatistics(**comparison_result.statistics)
            )
        else:
            # Format divergences
            formatted_divergences = []
            for div in comparison_result.divergences:
                if div.get("has_divergence"):
                    formatted_divergences.append(Divergence(
                        type=div["type"],
                        inputs=[InputValue(**inp) for inp in div.get("inputs", [])],
                        orig_output=OutputValue(**div["orig_output"]),
                        dec_output=OutputValue(**div["dec_output"]),
                        execution_traces=div.get("execution_traces")
                    ))
            
            return VerifyResponse(
                status="different",
                message=f"Found {len(formatted_divergences)} divergence(s)",
                equivalent=False,
                divergences=formatted_divergences,
                statistics=VerificationStatistics(**comparison_result.statistics)
            )
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.exception("Unexpected error during verification")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
    
    finally:
        # Cleanup temporary files
        if orig_path and os.path.exists(orig_path):
            try:
                os.remove(orig_path)
                logger.debug(f"Cleaned up: {orig_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {orig_path}: {e}")
        
        if dec_bin_path and os.path.exists(dec_bin_path):
            try:
                os.remove(dec_bin_path)
                logger.debug(f"Cleaned up: {dec_bin_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {dec_bin_path}: {e}")


@app.post("/analyze-binary", response_model=BinaryInfoResponse, tags=["Analysis"])
async def analyze_binary(
    binary: UploadFile = File(..., description="Binary file to analyze")
):
    """
    Analyze a binary and return metadata.
    
    Useful for understanding the binary structure before verification.
    """
    logger.info(f"Analyzing binary: {binary.filename}")
    
    bin_path = None
    
    try:
        # Save binary
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            content = await binary.read()
            tmp.write(content)
            bin_path = tmp.name
        
        # Load with angr
        try:
            from vexsym.core.loader import load_projects
            import angr
            
            proj = angr.Project(bin_path, auto_load_libs=False)
            
            # Get info
            info = get_project_info(proj)
            functions = list_all_functions(proj)
            
            return BinaryInfoResponse(
                filename=binary.filename,
                architecture=info["architecture"],
                bits=info["bits"],
                entry_point=info["entry_point"],
                functions=[FunctionInfo(**f) for f in functions[:100]]  # Limit to 100
            )
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise HTTPException(status_code=400, detail=f"Analysis failed: {str(e)}")
    
    finally:
        if bin_path and os.path.exists(bin_path):
            try:
                os.remove(bin_path)
            except Exception as e:
                logger.warning(f"Failed to cleanup {bin_path}: {e}")


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors."""
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Internal server error",
            "detail": str(exc)
        }
    )


if __name__ == "__main__":
    import uvicorn
    main()


def main():
    """Entry point for ``vexsym-server`` console script."""
    import uvicorn

    uvicorn.run(
        "vexsym.api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
