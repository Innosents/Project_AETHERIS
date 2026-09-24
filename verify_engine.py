from pathlib import Path
from loguru import logger
from aetheris.agent.orchestrator import LlamaOrchestrator

def verify():
    logger.info("Initializing AETHERIS Memory-Native Engine Verification...")
    model_dir = Path(".local_models")
    
    if not model_dir.exists():
        logger.error(".local_models/ directory does not exist.")
        return

    gguf_files = list(model_dir.glob("*.gguf"))
    
    if not gguf_files:
        logger.error("No GGUF weight binaries detected in .local_models/. Please drop your Llama 3.1 weight file here.")
        return

    target_model = gguf_files[0]
    logger.info(f"Target model located: {target_model}")

    # Instantiate the Strategic Commander with local RAM allocation
    orchestrator = LlamaOrchestrator(model_path=str(target_model))
    
    if orchestrator.llm:
        logger.success("SUCCESS: Memory-native GGUF weights successfully loaded into system RAM.")
    else:
        logger.error("FAILURE: LlamaOrchestrator failed to allocate model weights.")

if __name__ == "__main__":
    verify()