"""GlassScope Studio — Light-themed reverse engineering studio for Kali Linux.

Core package: parsers and scanners used by the GUI. Every function here is
written defensively: it returns structured results and warnings instead of
raising, so a malformed target can never crash the app.
"""

__version__ = "1.1.0"
APP_NAME = "GlassScope Studio"
APP_TAGLINE = "See through software."
