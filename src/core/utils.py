"""Helper utilities for the OpenAI-based lab runtime."""
from core.openai_runtime import types

async def chat_with_agent(agent, runner, message: str):
    """Send one message through the OpenAI runner and collect final text."""
    if runner is None:
        raise RuntimeError("OpenAI runner is unavailable. Install requirements and configure OPENAI_API_KEY.")
    user_id = "lab_user"
    session_id = "lab_session"
    try:
        await runner.session_service.create_session(app_name=runner.app_name, user_id=user_id, session_id=session_id)
    except Exception:
        pass
    content = types.Content(role="user", parts=[types.Part.from_text(text=message)])
    final_text = ""
    events = []
    async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
        events.append(event)
        if getattr(event, "content", None) and getattr(event.content, "parts", None):
            for part in event.content.parts:
                text = getattr(part, "text", None)
                if text:
                    final_text += text
    return final_text, events
