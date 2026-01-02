#!/usr/bin/env python3
"""
Icon Generator for Boundary Daemon
Creates black and white "spy vs spy" style icons for Windows.

Usage:
    python generate_icons.py

Requires: Pillow (pip install Pillow)
"""

import io
import struct
import math
from pathlib import Path

try:
    from PIL import Image, ImageDraw
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("Warning: Pillow not installed. Install with: pip install Pillow")


def draw_boundary_eye(draw, size, fill_bg='white', fill_fg='black'):
    """
    Draw the main boundary daemon icon - an all-seeing eye within a hexagonal boundary.
    Spy vs spy style: high contrast, angular, menacing.
    """
    w, h = size
    cx, cy = w // 2, h // 2

    # Background
    draw.rectangle([0, 0, w-1, h-1], fill=fill_bg)

    # Scale factor
    s = min(w, h) / 64

    # Outer hexagonal boundary (the "perimeter")
    hex_radius = int(28 * s)
    hex_points = []
    for i in range(6):
        angle = math.radians(60 * i - 30)
        px = cx + hex_radius * math.cos(angle)
        py = cy + hex_radius * math.sin(angle)
        hex_points.append((px, py))

    # Draw thick hexagon outline
    line_width = max(2, int(3 * s))
    draw.polygon(hex_points, outline=fill_fg, fill=None)
    for i in range(len(hex_points)):
        p1 = hex_points[i]
        p2 = hex_points[(i + 1) % len(hex_points)]
        draw.line([p1, p2], fill=fill_fg, width=line_width)

    # Inner eye shape (almond/pointed ellipse)
    eye_w = int(20 * s)
    eye_h = int(10 * s)

    # Draw eye outline with sharp points (spy style)
    eye_points = []
    # Left point
    eye_points.append((cx - eye_w, cy))
    # Top curve
    for i in range(1, 10):
        t = i / 10
        x = cx - eye_w + (2 * eye_w * t)
        y = cy - eye_h * math.sin(math.pi * t)
        eye_points.append((x, y))
    # Right point
    eye_points.append((cx + eye_w, cy))
    # Bottom curve
    for i in range(9, 0, -1):
        t = i / 10
        x = cx - eye_w + (2 * eye_w * t)
        y = cy + eye_h * math.sin(math.pi * t)
        eye_points.append((x, y))

    draw.polygon(eye_points, fill=fill_fg)

    # Pupil (white circle in the eye)
    pupil_r = int(5 * s)
    draw.ellipse([cx - pupil_r, cy - pupil_r, cx + pupil_r, cy + pupil_r], fill=fill_bg)

    # Inner pupil (black dot)
    inner_r = int(2 * s)
    draw.ellipse([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], fill=fill_fg)

    # Glint (small white highlight)
    glint_r = max(1, int(1 * s))
    glint_x = cx - int(2 * s)
    glint_y = cy - int(2 * s)
    draw.ellipse([glint_x - glint_r, glint_y - glint_r,
                  glint_x + glint_r, glint_y + glint_r], fill=fill_bg)


def draw_mode_icon(draw, size, mode, fill_bg='white', fill_fg='black'):
    """
    Draw mode-specific tray icons with spy vs spy aesthetic.
    """
    w, h = size
    cx, cy = w // 2, h // 2
    s = min(w, h) / 32

    draw.rectangle([0, 0, w-1, h-1], fill=fill_bg)

    if mode == 'OPEN':
        # Open eye - wide awake, watching
        draw_spy_eye(draw, cx, cy, s, fill_fg, fill_bg, open_amount=1.0)

    elif mode == 'RESTRICTED':
        # Narrowed eye - suspicious, alert
        draw_spy_eye(draw, cx, cy, s, fill_fg, fill_bg, open_amount=0.6)
        # Add small exclamation marks
        draw_exclamation(draw, cx - int(10*s), cy - int(8*s), s*0.5, fill_fg)

    elif mode == 'TRUSTED':
        # Eye with checkmark overlay
        draw_spy_eye(draw, cx, cy, s, fill_fg, fill_bg, open_amount=0.8)
        draw_checkmark(draw, cx + int(6*s), cy + int(6*s), s*0.8, fill_fg)

    elif mode == 'AIRGAP':
        # Eye behind bars/fence
        draw_spy_eye(draw, cx, cy, s, fill_fg, fill_bg, open_amount=0.7)
        # Vertical bars
        bar_w = max(1, int(1.5 * s))
        for i in range(-2, 3):
            x = cx + int(i * 5 * s)
            draw.line([(x, cy - int(12*s)), (x, cy + int(12*s))],
                     fill=fill_fg, width=bar_w)

    elif mode == 'COLDROOM':
        # Eye with snowflake/frozen effect
        draw_spy_eye(draw, cx, cy, s, fill_fg, fill_bg, open_amount=0.5)
        # Snowflake asterisk pattern
        for angle in range(0, 360, 60):
            rad = math.radians(angle)
            x1 = cx + int(8 * s * math.cos(rad))
            y1 = cy + int(8 * s * math.sin(rad))
            x2 = cx + int(14 * s * math.cos(rad))
            y2 = cy + int(14 * s * math.sin(rad))
            draw.line([(x1, y1), (x2, y2)], fill=fill_fg, width=max(1, int(s)))

    elif mode == 'LOCKDOWN':
        # X'd out eye - closed/blocked
        draw_spy_eye(draw, cx, cy, s, fill_fg, fill_bg, open_amount=0.3)
        # Big X over everything
        line_w = max(2, int(2 * s))
        offset = int(12 * s)
        draw.line([(cx - offset, cy - offset), (cx + offset, cy + offset)],
                 fill=fill_fg, width=line_w)
        draw.line([(cx + offset, cy - offset), (cx - offset, cy + offset)],
                 fill=fill_fg, width=line_w)

    elif mode == 'HEALTHY':
        # Happy eye with pulse/heartbeat
        draw_spy_eye(draw, cx, cy - int(2*s), s, fill_fg, fill_bg, open_amount=1.0)
        # Heartbeat line
        pts = [
            (cx - int(12*s), cy + int(10*s)),
            (cx - int(6*s), cy + int(10*s)),
            (cx - int(4*s), cy + int(6*s)),
            (cx - int(2*s), cy + int(14*s)),
            (cx, cy + int(8*s)),
            (cx + int(2*s), cy + int(10*s)),
            (cx + int(12*s), cy + int(10*s)),
        ]
        draw.line(pts, fill=fill_fg, width=max(1, int(s)))

    elif mode == 'DEGRADED':
        # Droopy/tired eye
        draw_spy_eye(draw, cx, cy, s, fill_fg, fill_bg, open_amount=0.5, droopy=True)

    elif mode == 'UNHEALTHY':
        # Skull/danger
        draw_skull(draw, cx, cy, s, fill_fg, fill_bg)


def draw_spy_eye(draw, cx, cy, s, fill_fg, fill_bg, open_amount=1.0, droopy=False):
    """Draw a single spy-style eye with adjustable openness."""
    eye_w = int(12 * s)
    eye_h = int(6 * s * open_amount)

    if eye_h < 2:
        # Just a line for nearly closed
        draw.line([(cx - eye_w, cy), (cx + eye_w, cy)], fill=fill_fg, width=max(2, int(2*s)))
        return

    # Eye shape points
    eye_points = []
    steps = 12

    # Create almond shape
    for i in range(steps + 1):
        t = i / steps
        x = cx - eye_w + (2 * eye_w * t)
        # Top curve (may droop on one side)
        droop_offset = 0
        if droopy and t > 0.5:
            droop_offset = int(3 * s * (t - 0.5))
        y = cy - eye_h * math.sin(math.pi * t) + droop_offset
        eye_points.append((x, y))

    for i in range(steps, -1, -1):
        t = i / steps
        x = cx - eye_w + (2 * eye_w * t)
        y = cy + eye_h * math.sin(math.pi * t)
        eye_points.append((x, y))

    draw.polygon(eye_points, fill=fill_fg)

    # Pupil
    pupil_r = int(3 * s * open_amount)
    if pupil_r >= 1:
        draw.ellipse([cx - pupil_r, cy - pupil_r, cx + pupil_r, cy + pupil_r], fill=fill_bg)

        # Inner dot
        inner_r = max(1, int(1 * s))
        draw.ellipse([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], fill=fill_fg)


def draw_checkmark(draw, cx, cy, s, fill):
    """Draw a checkmark."""
    pts = [
        (cx - int(3*s), cy),
        (cx - int(1*s), cy + int(3*s)),
        (cx + int(4*s), cy - int(3*s)),
    ]
    draw.line(pts, fill=fill, width=max(2, int(2*s)))


def draw_exclamation(draw, cx, cy, s, fill):
    """Draw an exclamation mark."""
    # Dot
    r = max(1, int(1*s))
    draw.ellipse([cx-r, cy+int(4*s)-r, cx+r, cy+int(4*s)+r], fill=fill)
    # Line
    draw.line([(cx, cy-int(4*s)), (cx, cy+int(1*s))], fill=fill, width=max(1, int(2*s)))


def draw_skull(draw, cx, cy, s, fill_fg, fill_bg):
    """Draw a simple skull icon."""
    # Skull outline (circle-ish)
    r = int(10 * s)
    draw.ellipse([cx-r, cy-r-int(2*s), cx+r, cy+r-int(2*s)], fill=fill_fg)

    # Jaw (slightly smaller)
    jaw_r = int(7 * s)
    draw.rectangle([cx-jaw_r, cy, cx+jaw_r, cy+int(6*s)], fill=fill_fg)

    # Eye sockets
    eye_r = int(3 * s)
    eye_offset = int(4 * s)
    draw.ellipse([cx-eye_offset-eye_r, cy-int(4*s)-eye_r,
                  cx-eye_offset+eye_r, cy-int(4*s)+eye_r], fill=fill_bg)
    draw.ellipse([cx+eye_offset-eye_r, cy-int(4*s)-eye_r,
                  cx+eye_offset+eye_r, cy-int(4*s)+eye_r], fill=fill_bg)

    # Nose hole
    nose_r = int(1.5 * s)
    draw.polygon([(cx, cy-int(1*s)), (cx-nose_r, cy+int(1*s)), (cx+nose_r, cy+int(1*s))], fill=fill_bg)

    # Teeth
    tooth_w = int(2 * s)
    for i in range(-2, 3):
        tx = cx + int(i * 2.5 * s)
        draw.rectangle([tx-int(tooth_w/2), cy+int(2*s), tx+int(tooth_w/2), cy+int(5*s)],
                      outline=fill_bg, fill=fill_fg)


def create_ico_file(images, output_path):
    """
    Create an ICO file from a list of PIL Image objects.

    Args:
        images: List of (size, image) tuples where size is (width, height)
        output_path: Path to save the ICO file
    """
    # ICO header
    ico_header = struct.pack('<HHH', 0, 1, len(images))  # Reserved, Type (1=ICO), Count

    # Prepare image data
    image_entries = []
    image_data = []
    data_offset = 6 + (16 * len(images))  # Header + directory entries

    for size, img in images:
        # Convert to RGBA if needed
        if img.mode != 'RGBA':
            img = img.convert('RGBA')

        # Save as PNG in memory
        png_buffer = io.BytesIO()
        img.save(png_buffer, format='PNG')
        png_data = png_buffer.getvalue()

        # Create directory entry
        width = size[0] if size[0] < 256 else 0
        height = size[1] if size[1] < 256 else 0

        entry = struct.pack('<BBBBHHII',
            width,          # Width (0 = 256)
            height,         # Height (0 = 256)
            0,              # Color count (0 for 32-bit)
            0,              # Reserved
            1,              # Color planes
            32,             # Bits per pixel
            len(png_data),  # Size of image data
            data_offset     # Offset to image data
        )

        image_entries.append(entry)
        image_data.append(png_data)
        data_offset += len(png_data)

    # Write ICO file
    with open(output_path, 'wb') as f:
        f.write(ico_header)
        for entry in image_entries:
            f.write(entry)
        for data in image_data:
            f.write(data)


def generate_main_icon(output_dir):
    """Generate the main boundary daemon icon."""
    if not HAS_PIL:
        print("Cannot generate icons without Pillow")
        return False

    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    images = []

    for size in sizes:
        img = Image.new('RGBA', size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(img)
        draw_boundary_eye(draw, size, fill_bg='white', fill_fg='black')
        images.append((size, img))

        # Also save individual PNG for reference
        if size[0] in [32, 256]:
            img.save(output_dir / f'icon_{size[0]}.png')

    # Create ICO file
    create_ico_file(images, output_dir / 'icon.ico')
    print(f"Created: {output_dir / 'icon.ico'}")

    return True


def generate_mode_icons(output_dir):
    """Generate tray icons for each daemon mode."""
    if not HAS_PIL:
        print("Cannot generate icons without Pillow")
        return False

    modes = ['OPEN', 'RESTRICTED', 'TRUSTED', 'AIRGAP', 'COLDROOM', 'LOCKDOWN',
             'HEALTHY', 'DEGRADED', 'UNHEALTHY']

    sizes = [(16, 16), (24, 24), (32, 32), (48, 48)]

    for mode in modes:
        images = []

        for size in sizes:
            img = Image.new('RGBA', size, (255, 255, 255, 0))
            draw = ImageDraw.Draw(img)
            draw_mode_icon(draw, size, mode, fill_bg='white', fill_fg='black')
            images.append((size, img))

        # Create ICO file for this mode
        ico_path = output_dir / f'tray_{mode.lower()}.ico'
        create_ico_file(images, ico_path)
        print(f"Created: {ico_path}")

        # Also create inverted version (white on black) for dark mode
        images_dark = []
        for size in sizes:
            img = Image.new('RGBA', size, (0, 0, 0, 255))
            draw = ImageDraw.Draw(img)
            draw_mode_icon(draw, size, mode, fill_bg='black', fill_fg='white')
            images_dark.append((size, img))

        ico_dark_path = output_dir / f'tray_{mode.lower()}_dark.ico'
        create_ico_file(images_dark, ico_dark_path)
        print(f"Created: {ico_dark_path}")

    return True


def main():
    """Generate all icons for the boundary daemon."""
    output_dir = Path(__file__).parent

    print("=" * 60)
    print("Boundary Daemon Icon Generator")
    print("Style: Black & White 'Spy vs Spy'")
    print("=" * 60)
    print()

    if not HAS_PIL:
        print("ERROR: Pillow is required to generate icons.")
        print("Install with: pip install Pillow")
        print()
        print("Alternatively, you can use the fallback PNG files if available.")
        return 1

    print("Generating main application icon...")
    generate_main_icon(output_dir)
    print()

    print("Generating mode-specific tray icons...")
    generate_mode_icons(output_dir)
    print()

    print("=" * 60)
    print("Icon generation complete!")
    print()
    print("Files created:")
    print(f"  - {output_dir / 'icon.ico'} (main app icon)")
    print(f"  - {output_dir / 'tray_*.ico'} (tray icons for each mode)")
    print(f"  - {output_dir / 'tray_*_dark.ico'} (dark mode variants)")
    print("=" * 60)

    return 0


if __name__ == '__main__':
    exit(main())
