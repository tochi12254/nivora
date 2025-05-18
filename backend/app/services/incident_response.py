# backend/app/services/incident_response.py
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import logging
from datetime import datetime
import socketio
import asyncio

logger = logging.getLogger("incident_response")


@dataclass
class ResponseAction:
    name: str
    action_type: str  # 'block', 'quarantine', 'alert', 'notify'
    parameters: Dict
    timeout: int = 60  # seconds
    is_active: bool = True


@dataclass
class ResponseWorkflow:
    name: str
    trigger_conditions: List[Dict]
    actions: List[ResponseAction]
    priority: int = 5  # 1-10
    cooldown: int = 300  # seconds


class IncidentResponseEngine:
    def __init__(self, sio: socketio.AsyncServer):
        self.sio = sio
        self.workflows = self._load_default_workflows()
        self.active_incidents = {}
        self.lock = asyncio.Lock()

    def _load_default_workflows(self) -> Dict[str, ResponseWorkflow]:
        return {
            "malware_containment": ResponseWorkflow(
                name="Malware Containment",
                trigger_conditions=[
                    {"field": "severity", "operator": ">=", "value": "high"},
                    {"field": "tags", "operator": "contains", "value": "malware"},
                ],
                actions=[
                    ResponseAction(
                        name="Block Source IP",
                        action_type="block",
                        parameters={"target": "source_ip", "duration": 3600},
                    ),
                    ResponseAction(
                        name="Quarantine Host",
                        action_type="quarantine",
                        parameters={"host": "${source_ip}"},
                    ),
                ],
            ),
            "bruteforce_response": ResponseWorkflow(
                name="Brute Force Protection",
                trigger_conditions=[
                    {"field": "event_type", "operator": "==", "value": "auth_failure"},
                    {"field": "count", "operator": ">", "value": 5},
                ],
                actions=[
                    ResponseAction(
                        name="Temp Block IP",
                        action_type="block",
                        parameters={"target": "source_ip", "duration": 900},
                    )
                ],
            ),
        }

    async def handle_event(self, event: Dict):
        """Process event through all workflows"""
        async with self.lock:
            incident_id = event.get("id") or self._generate_incident_id(event)

            if incident_id in self.active_incidents:
                return  # Already processing

            self.active_incidents[incident_id] = {
                "created": datetime.utcnow(),
                "status": "processing",
            }

        try:
            matched_workflows = [
                wf
                for wf in self.workflows.values()
                if self._matches_conditions(event, wf.trigger_conditions)
            ]

            if matched_workflows:
                await self._execute_response(event, matched_workflows, incident_id)

        finally:
            async with self.lock:
                self.active_incidents[incident_id]["status"] = "completed"
                self.active_incidents[incident_id]["completed"] = datetime.utcnow()

    async def _execute_response(
        self, event: Dict, workflows: List[ResponseWorkflow], incident_id: str
    ):
        """Execute all response actions"""
        results = []

        for workflow in sorted(workflows, key=lambda w: w.priority):
            for action in workflow.actions:
                if not action.is_active:
                    continue

                try:
                    result = await self._execute_action(action, event)
                    results.append(
                        {
                            "workflow": workflow.name,
                            "action": action.name,
                            "status": "success" if result else "failed",
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )

                    # Emit action taken
                    await self.sio.emit(
                        "response_action",
                        {
                            "incident_id": incident_id,
                            "action": action.name,
                            "parameters": self._resolve_parameters(
                                action.parameters, event
                            ),
                            "workflow": workflow.name,
                            "event": event,
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )

                except Exception as e:
                    logger.error(f"Action failed: {action.name} - {str(e)}")
                    results.append(
                        {
                            "workflow": workflow.name,
                            "action": action.name,
                            "status": "error",
                            "error": str(e),
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )

        # Send full response report
        await self.sio.emit(
            "incident_response",
            {
                "incident_id": incident_id,
                "event": event,
                "actions_taken": results,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    async def _execute_action(self, action: ResponseAction, context: Dict) -> bool:
        """Execute single response action"""
        params = self._resolve_parameters(action.parameters, context)

        if action.action_type == "block":
            return await self._block_ip(params["target"], params.get("duration", 300))
        elif action.action_type == "quarantine":
            return await self._quarantine_host(params["host"])
        # Add other action types

        return False

    def _resolve_parameters(self, parameters: Dict, context: Dict) -> Dict:
        """Resolve templated parameters (e.g., ${source_ip})"""
        resolved = {}
        for k, v in parameters.items():
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                key = v[2:-1]
                resolved[k] = context.get(key)
            else:
                resolved[k] = v
        return resolved
