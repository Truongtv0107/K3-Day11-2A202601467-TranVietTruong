from __future__ import annotations
import json
from dataclasses import dataclass,field
from pathlib import Path
@dataclass
class Alert: metric:str; value:float; threshold:float; message:str
@dataclass
class MonitoringAlert:
    block_rate_threshold:float=.5; rate_limit_hit_threshold:int=5; judge_fail_rate_threshold:float=.3; alerts:list[Alert]=field(default_factory=list); total_requests:int=0; blocked_requests:int=0; rate_limit_hits:int=0; judge_checks:int=0; judge_fails:int=0
    def check_metrics(self):
        self.alerts=[]; snap=self.snapshot()
        if snap["block_rate"]>self.block_rate_threshold: self.alerts.append(Alert("block_rate",snap["block_rate"],self.block_rate_threshold,"High block rate may indicate an attack campaign or false positives."))
        if self.rate_limit_hits>=self.rate_limit_hit_threshold: self.alerts.append(Alert("rate_limit_hits",self.rate_limit_hits,self.rate_limit_hit_threshold,"Rate-limit threshold reached."))
        if snap["judge_fail_rate"]>self.judge_fail_rate_threshold: self.alerts.append(Alert("judge_fail_rate",snap["judge_fail_rate"],self.judge_fail_rate_threshold,"Judge failure rate is elevated."))
        return self.alerts
    def export_json(self,filepath="outputs/metrics.json"):
        self.check_metrics(); p=Path(filepath); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(self.snapshot(),ensure_ascii=False,indent=2),encoding="utf-8"); return str(p)
    def snapshot(self):
        br=self.blocked_requests/self.total_requests if self.total_requests else 0.; jr=self.judge_fails/self.judge_checks if self.judge_checks else 0.
        return {"total_requests":self.total_requests,"blocked_requests":self.blocked_requests,"block_rate":br,"rate_limit_hits":self.rate_limit_hits,"judge_checks":self.judge_checks,"judge_fails":self.judge_fails,"judge_fail_rate":jr,"alerts":[a.__dict__ for a in self.alerts]}
