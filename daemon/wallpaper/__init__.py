"""
Wallpaper Integration Module

Provides integration with Lively Wallpaper to run the Matrix dashboard
as an animated Windows desktop wallpaper.
"""

from daemon.wallpaper.lively import LivelyWallpaper, LivelyNotFoundError

__all__ = ['LivelyWallpaper', 'LivelyNotFoundError']
