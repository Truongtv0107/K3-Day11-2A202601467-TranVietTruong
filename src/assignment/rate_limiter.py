from __future__ import annotations
from collections import defaultdict, deque
import time
from core.openai_runtime import base_plugin, types

class RateLimitPlugin(base_plugin.BasePlugin):
    """Per-user sliding-window limiter against flooding and cost abuse."""
    def __init__(self,max_requests:int=10,window_seconds:int=60):
        super().__init__(name="rate_limiter"); self.max_requests=max_requests; self.window_seconds=window_seconds; self.user_windows=defaultdict(deque); self.blocked_count=0; self.total_count=0
    def _block_response(self,message): return types.Content(role="model",parts=[types.Part.from_text(text=message)])
    async def on_user_message_callback(self,*,invocation_context,user_message):
        self.total_count+=1; user_id=getattr(invocation_context,"user_id",None) or "anonymous"; now=time.time(); window=self.user_windows[user_id]
        cutoff=now-self.window_seconds
        while window and window[0] <= cutoff: window.popleft()
        if len(window)>=self.max_requests:
            self.blocked_count+=1; wait=max(0,self.window_seconds-(now-window[0])); return self._block_response(f"Rate limit exceeded. Try again in {wait:.0f}s.")
        window.append(now); return None
