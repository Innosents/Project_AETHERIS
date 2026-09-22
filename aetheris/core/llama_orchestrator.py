"""Sovereign agent core orchestration with injected module deployment."""

import ast
import json
import traceback
from typing import Any, Dict, Optional

from aetheris.core.ports.llama_orchestrator_port import (
    ModuleDeployerPort,
    MutationDeploymentRequest,
    MutationDeploymentResult,
    SelfHealingContext,
    SovereignAgentPort,
)
from aetheris.core.safety.scope_guard import (
    AetherisExecutionVisitor,
    CognitiveSecurityFault,
    ScopeGuard,
)


class SovereignAgent(SovereignAgentPort):
    """Validates generated mutations and delegates deployment to an adapter."""

    def __init__(self, module_deployer: Optional[ModuleDeployerPort] = None) -> None:
        self.adapters: Dict[str, type] = {}
        self.schema = {
            "target_domain": ["l2_physical", "l3_network", "hardware_telemetry", "self_healing"],
            "class_name": "str",
            "payload": "str",
        }
        self.redis_client: Any = None
        if module_deployer is None:
            from aetheris.infrastructure.adapters.deployment.dynamic_module_deployer import (
                DynamicModuleDeployer,
            )

            module_deployer = DynamicModuleDeployer()
        self.module_deployer = module_deployer

    async def _execute_local_deployment(
        self,
        mutation_payload: str | MutationDeploymentRequest,
        target_domain: Optional[str] = None,
        class_name: Optional[str] = None,
        module_path: Optional[str] = None,
        anomaly_vector: Optional[Dict[str, Any]] = None,
        blueprint_raw: str = "",
        depth: int = 0,
    ) -> MutationDeploymentResult:
        """Validate a mutation in core and delegate materialization to the adapter."""
        request = (
            mutation_payload
            if isinstance(mutation_payload, MutationDeploymentRequest)
            else MutationDeploymentRequest(
                mutation_payload=mutation_payload,
                target_domain=target_domain or "",
                class_name=class_name or "",
                module_path=module_path or "",
                anomaly_vector=anomaly_vector or {},
                blueprint_raw=blueprint_raw,
                depth=depth,
            )
        )

        try:
            parsed_ast = ast.parse(request.mutation_payload)
            visitor = AetherisExecutionVisitor()
            visitor.visit(parsed_ast)
        except SyntaxError as exc:
            await self._execute_self_healing_loop(
                SelfHealingContext(
                    blueprint_raw=request.blueprint_raw,
                    fault_message=f"Syntax validation failed: {exc}",
                    current_depth=request.depth,
                )
            )
            return MutationDeploymentResult(
                success=False,
                class_name=request.class_name,
                module_path=request.module_path,
                error_message=str(exc),
            )
        except CognitiveSecurityFault as exc:
            print(f"[SECURITY FAULT] {exc}")
            await self._execute_self_healing_loop(
                SelfHealingContext(
                    blueprint_raw=request.blueprint_raw,
                    fault_message=str(exc),
                    current_depth=request.depth,
                )
            )
            return MutationDeploymentResult(
                success=False,
                class_name=request.class_name,
                module_path=request.module_path,
                error_message=str(exc),
            )

        if not ScopeGuard.authorize_module_mutation(request.module_path):
            message = f"Domain isolation breach attempted at: {request.module_path}"
            await self._execute_self_healing_loop(
                SelfHealingContext(
                    blueprint_raw=request.blueprint_raw,
                    fault_message=message,
                    current_depth=request.depth,
                )
            )
            return MutationDeploymentResult(
                success=False,
                class_name=request.class_name,
                module_path=request.module_path,
                error_message=message,
            )

        try:
            success, probe_class, error_message = self.module_deployer.deploy_and_load_module(request)
            if not success or probe_class is None:
                message = error_message or "Dynamic module deployment failed"
                await self._execute_self_healing_loop(
                    SelfHealingContext(
                        blueprint_raw=request.blueprint_raw,
                        fault_message=message,
                        current_depth=request.depth,
                    )
                )
                return MutationDeploymentResult(
                    success=False,
                    class_name=request.class_name,
                    module_path=request.module_path,
                    error_message=message,
                )

            self.adapters[request.class_name] = probe_class
            probe_instance = probe_class(
                target_ip=request.anomaly_vector.get("target_ip", "127.0.0.1"),
                telemetry_context=request.anomaly_vector,
            )
            probe_identifier = getattr(probe_instance, "probe_id", request.class_name)
            print(f"[*] Igniting polymorphic execution matrix for probe ID: {probe_identifier}")
            telemetry_result = await probe_instance.execute()
            print(f"[+] Execution cycle complete. Matrix extraction: {json.dumps(telemetry_result)}")

            if self.redis_client:
                await self.redis_client.lpush(
                    "aetheris:telemetry:results",
                    json.dumps(telemetry_result),
                )
            else:
                print("[!] Warning: redis_client not bound. Telemetry push bypassed.")

            return MutationDeploymentResult(
                success=True,
                class_name=request.class_name,
                module_path=request.module_path,
            )
        except Exception as exc:
            fault_trace = traceback.format_exc()
            print(f"[!] RUNTIME EXECUTION FAULT. Tracing stack...\n{fault_trace}")
            await self._execute_self_healing_loop(
                SelfHealingContext(
                    blueprint_raw=request.blueprint_raw,
                    fault_message=fault_trace,
                    current_depth=request.depth,
                )
            )
            return MutationDeploymentResult(
                success=False,
                class_name=request.class_name,
                module_path=request.module_path,
                error_message=fault_trace,
            )

    async def _execute_self_healing_loop(self, context: SelfHealingContext) -> None:
        """Route validated deployment faults to the self-healing workflow."""
        return None


__all__ = ["SovereignAgent"]
