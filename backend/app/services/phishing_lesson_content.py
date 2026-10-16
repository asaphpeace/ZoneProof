"""
Real, authored content for the in-app micro-lesson shown to a recipient
who clicked or entered credentials (Coverage Map plan phishing
transformation, Phase 2). Every reference platform researched
(KnowBe4, Microsoft Defender Attack Simulation Training, Proofpoint,
Hoxhunt) closes the loop this way — a clicker gets a short lesson, not
just a "you failed" notice.

Personalization is honest, not fabricated: get_lesson_content() only
cites a specific red flag if the matching phrase is actually present in
the real subject/body that was sent this cycle (PhishingCampaign.
subject_sent / body_html_sent). When nothing matches — a heavily
edited static override, or LLM-generated copy that didn't happen to use
the anticipated phrasing — it falls back to a category-appropriate
generic flag list rather than asserting something that isn't there.

Design constraints (this reaches real employees at real companies):
- No "you failed" language anywhere — the tone stays plain and helpful.
- The reflection question has no scored right/wrong shown to the
  recipient; reflection_response is recorded for reporting, never
  graded in front of them.
- Short: what happened, the real red flags, one reflective question.
  Not a course.
"""
from __future__ import annotations


def _flag(phrase: str, explanation: str) -> dict:
    return {"phrase": phrase, "explanation": explanation}


# One entry per built-in lure category. `flags` are checked, in order,
# against the real sent subject+body — only the ones that actually match
# are shown. `generic_flags` are the fallback when none match (a heavily
# customized static override, or unrecognized LLM phrasing).
_LESSON_CATEGORIES: dict[str, dict] = {
    "password-expiry": {
        "title": "The \"your password is about to expire\" email",
        "what_happened": (
            "This email claimed your password was about to expire and asked you to "
            "confirm your credentials through a link before a deadline. That's a "
            "classic credential-harvesting pretext — the urgency is the point."
        ),
        "flags": [
            _flag("expire", "It created artificial urgency around a deadline — real IT password-rotation notices rarely demand action within hours."),
            _flag("confirm my password", "It asked you to \"confirm\" your password through an email link — no legitimate IT process ever asks you to type your password into a page you reached by clicking a link in an email."),
            _flag("24 hours", "The 24-hour countdown is a pressure tactic, not how real password-expiry systems usually communicate."),
        ],
        "generic_flags": [
            "A tight deadline on a routine account action.",
            "A request to \"confirm\" a password via an email link, rather than through your normal IT self-service portal.",
        ],
    },
    "shared-document": {
        "title": "The \"a document has been shared with you\" email",
        "what_happened": (
            "This email said a colleague shared a document and asked you to sign in "
            "to view it. Fake document-share notifications are one of the most common "
            "phishing pretexts, because \"sign in to view\" feels routine."
        ),
        "flags": [
            _flag("a colleague", "It didn't name the actual colleague — a vague \"a colleague\" is a sign the sender doesn't know who you'd expect this from."),
            _flag("sign in to view", "It asked you to sign in through an email link to view a document — real file-sharing tools you're already logged into rarely require this."),
            _flag("requires your review", "Vague urgency (\"requires your review\") with no detail about what the document actually is."),
        ],
        "generic_flags": [
            "A shared-document notification that doesn't name who actually shared it.",
            "A request to sign in again through an email link, rather than opening the file from a tool you're already logged into.",
        ],
    },
    "it-support-request": {
        "title": "The \"IT detected unusual sign-in activity\" email",
        "what_happened": (
            "This email claimed IT detected unusual sign-in activity and restricted "
            "your account, asking you to verify your identity to restore access. "
            "Fear of losing access is a powerful, common phishing lever."
        ),
        "flags": [
            _flag("unusual sign-in", "\"Unusual activity\" was never described specifically — a real security team's alert would usually name a location, device, or time."),
            _flag("temporarily restricted", "The claim your access was already restricted is designed to make you act before you think — real IT lockouts come through channels you already trust (a phone call, a known ticketing system), not a first-contact email link."),
            _flag("verify my account", "It asked you to \"verify\" your identity through a link rather than directing you to your organization's actual IT support process."),
        ],
        "generic_flags": [
            "A vague claim of \"unusual activity\" with no specific detail.",
            "Pressure to act immediately to avoid losing account access.",
        ],
    },
    "generic": {
        "title": "This simulated email",
        "what_happened": (
            "This email was a simulated phishing test — content generated fresh for "
            "this send, so it won't always match a fixed script. The same handful of "
            "red flags show up across almost every real phishing attempt, regardless "
            "of the specific story."
        ),
        "flags": [],
        "generic_flags": [
            "Urgency or a deadline pushing you to act before you'd normally stop and check.",
            "A request to click a link and then enter credentials, rather than going directly to a site you already trust.",
            "A generic greeting or vague sender identity instead of something specific to you.",
            "Tone or phrasing that doesn't quite match how this sender normally writes to you.",
        ],
    },
}

REFLECTION_OPTIONS: list[dict] = [
    {"key": "urgency", "label": "The urgency/deadline language"},
    {"key": "link_then_credentials", "label": "Being asked to click a link, then enter credentials"},
    {"key": "vague_sender", "label": "A vague or unfamiliar sender"},
    {"key": "tone_mismatch", "label": "Something about the tone felt off"},
    {"key": "not_sure", "label": "Honestly, nothing stood out to me"},
]


def get_lesson_content(lure_category: str, subject_sent: str | None, body_html_sent: str | None) -> dict:
    """Returns the lesson to render for this campaign. Only cites a
    specific red flag when its phrase is genuinely present in the real
    sent text — never asserts one that isn't there."""
    category = _LESSON_CATEGORIES.get(lure_category, _LESSON_CATEGORIES["generic"])
    haystack = f"{subject_sent or ''} {body_html_sent or ''}".lower()

    matched_flags = [f["explanation"] for f in category["flags"] if f["phrase"].lower() in haystack]
    if not matched_flags:
        matched_flags = category["generic_flags"]

    return {
        "title": category["title"],
        "what_happened": category["what_happened"],
        "red_flags": matched_flags,
        "reflection_options": REFLECTION_OPTIONS,
    }
