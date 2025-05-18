# backend/app/services/mitre_attack.py

from backend.libs.mitreattack.mitreattack.stix20 import MitreAttackData
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger("mitre")


class MITREAttackMapper:
    def __init__(self):
        self.attack_data = MitreAttackData("./data/enterprise-attack.json")
        self.techniques = self._load_techniques()
        self.matrix = self._build_matrix()

    def _load_techniques(self) -> Dict[str, Dict]:
        """Load MITRE ATT&CK techniques with metadata"""
        return {
            tech.id: {
                "id": tech.id,
                "name": tech.name,
                "tactic": [
                    t.name for t in self.attack_data.get_tactics_by_technique(tech)
                ],
                "platforms": tech.x_mitre_platforms,
                "data_sources": tech.x_mitre_data_sources,
                "url": f"https://attack.mitre.org/techniques/{tech.id.split('.')[0]}/{tech.id.split('.')[1] if '.' in tech.id else ''}",
            }
            for tech in self.attack_data.get_techniques()
        }

    def _build_matrix(self) -> Dict[str, List]:
        """Build tactic->technique mapping"""
        matrix = {}
        for tactic in self.attack_data.get_tactics():
            matrix[tactic.name] = [
                tech.id for tech in self.attack_data.get_techniques_by_tactic(tactic)
            ]
        return matrix

    async def map_event(self, detection: Dict) -> Dict:
        """Map detection to MITRE ATT&CK"""
        matched = []

        # Check techniques by pattern
        for tech_id, tech in self.techniques.items():
            if self._matches_technique(detection, tech):
                matched.append(tech_id)

        if matched:
            return {
                "detection_id": detection.get("id"),
                "timestamp": datetime.utcnow().isoformat(),
                "mitre_techniques": matched,
                "mitre_tactics": list(
                    set(
                        tactic
                        for tech_id in matched
                        for tactic in self.techniques[tech_id]["tactic"]
                    )
                ),
                "confidence": self._calculate_confidence(detection, matched),
            }
        return None

    def _matches_technique(self, detection: Dict, technique: Dict) -> bool:
        """Determine if detection matches technique"""
        # Implement your matching logic here
        return any(
            source.lower() in detection.get("description", "").lower()
            for source in technique["data_sources"]
        )

    async def emit_mitre_event(self, detection: Dict):
        """Send MITRE-mapped event to clients"""
        mapped = await self.map_event(detection)
        if mapped:
            await self.sio.emit(
                "mitre_mapping",
                {**mapped, "original_event": detection, "mitre_matrix": self.matrix},
            )
