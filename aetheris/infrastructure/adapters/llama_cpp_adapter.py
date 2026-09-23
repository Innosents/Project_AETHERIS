import asyncio
import json
import logging
from typing import Optional, Any
try:
    from llama_cpp import Llama, LlamaGrammar
except ImportError:
    class _LlamaFallback:
        pass
    class _LlamaGrammarFallback:
        @classmethod
        def from_string(cls, *args, **kwargs):
            return cls()
    Llama = _LlamaFallback  # type: ignore
    LlamaGrammar = _LlamaGrammarFallback  # type: ignore
from aetheris.core.ports.agent_decision import ActionTensor, InferenceEnginePort

logger = logging.getLogger("aetheris.adapters.llama_cpp")

JSON_GRAMMAR = r'''
root ::= "{" ws "\"hardware_id\"" ws ":" ws string "," ws "\"action_code\"" ws ":" ws action "," ws "\"confidence\"" ws ":" ws number "," ws "\"reasoning\"" ws ":" ws string "}"
action ::= "\"ISOLATE\"" | "\"MONITOR\"" | "\"IGNORE\""
string ::= "\"" [^"]* "\""
number ::= [0-9]+ "." [0-9]+
ws ::= [ \t\n]*
'''

class LlamaCppInferenceAdapter(InferenceEnginePort):
    def __init__(
        self,
        model_path: str = "models/llama-3.1-8b-instruct.gguf",
        n_threads: int = 8,
        n_ctx: int = 4096,
        llm: Optional[Any] = None,
    ):
        self.model_path = model_path
        if llm is not None:
            self.llm = llm
        else:
            self.llm = Llama(
                model_path=model_path,
                n_ctx=n_ctx,
                n_threads=n_threads,
                n_gpu_layers=0,
                verbose=False
            )
        self.grammar = LlamaGrammar.from_string(JSON_GRAMMAR)

    def _sync_infer(self, prompt: str) -> str:
        response = self.llm(
            prompt,
            max_tokens=256,
            temperature=0.1,
            grammar=self.grammar
        )
        return response['choices'][0]['text']

    async def infer_decision(self, telemetry_json: str) -> ActionTensor:
        system_prompt = (
            "You are AETHERIS, an autonomous NDR security orchestrator. "
            "Analyze the following Layer 2 telemetry and output a strict JSON decision matrix. "
            "Determine if the hardware baseline variance dictates port isolation."
        )
        prompt = f"<|start_header_id|>system<|end_header_id|>\n{system_prompt}\n<|eot_id|><|start_header_id|>user<|end_header_id|>\n{telemetry_json}\n<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
        raw_output = await asyncio.to_thread(self._sync_infer, prompt)
        decision_dict = json.loads(raw_output)
        return ActionTensor(**decision_dict)

