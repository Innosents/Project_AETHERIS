"""Concrete adapter for validated dynamic module materialization."""

import importlib
import os
from typing import Optional, Tuple, Type

from aetheris.core.ports.llama_orchestrator_port import (
    ModuleDeployerPort,
    MutationDeploymentRequest,
)


class DynamicModuleDeployer(ModuleDeployerPort):
    """Writes an authorized module and resolves its requested class."""

    def deploy_and_load_module(
        self,
        request: MutationDeploymentRequest,
    ) -> Tuple[bool, Optional[type], Optional[str]]:
        try:
            os.makedirs(os.path.dirname(request.module_path), exist_ok=True)
            with open(request.module_path, "w", encoding="utf-8") as module_file:
                module_file.write(request.mutation_payload)

            dotted_path = (
                request.module_path.replace(".py", "")
                .replace("/", ".")
                .replace("\\", ".")
            )
            module = importlib.import_module(dotted_path)
            deployed_class = getattr(module, request.class_name, None)
            if deployed_class is None:
                return False, None, (
                    f"Class {request.class_name} not found in {dotted_path}"
                )
            return True, deployed_class, None
        except Exception as exc:
            return False, None, str(exc)


__all__ = ["DynamicModuleDeployer"]
