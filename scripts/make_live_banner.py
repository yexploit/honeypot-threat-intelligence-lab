"""Build a clearly animated live banner GIF for the honeypot lab README."""
from __future__ import annotations

import math
import random
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
BASE = ASSETS / "banner.png"
OUT = ASSETS / "banner.gif"

W, H = 920, 200
FRAMES = 24
DURATION_MS = 70


def load_base() -> Image.Image:
    img = Image.open(BASE).convert("RGB")
    if img.size != (W, H):
        img = img.resize((W, H), Image.Resampling.LANCZOS)
    return img


def neon_overlay(frame_idx: int, total: int) -> Image.Image:
    """Moving particles + sweep beam + edge glow."""
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    t = frame_idx / total
    phase = t * math.tau

    # Sweeping cyan scan beam
    beam_x = int((math.sin(phase) * 0.5 + 0.5) * (W + 160) - 80)
    for i, alpha in enumerate((18, 36, 70, 36, 18)):
        x = beam_x + (i - 2) * 10
        draw.rectangle([x, 0, x + 8, H], fill=(0, 255, 255, alpha))

    # Magenta counter-sweep
    beam2 = int((math.cos(phase * 0.85) * 0.5 + 0.5) * (W + 120) - 60)
    for i, alpha in enumerate((12, 28, 50, 28, 12)):
        x = beam2 + (i - 2) * 8
        draw.rectangle([x, 0, x + 6, H], fill=(255, 40, 200, alpha))

    # Floating honey/cyan particles
    rng = random.Random(42)
    for n in range(28):
        seed_x = rng.random()
        seed_y = rng.random()
        speed = 0.35 + rng.random() * 0.9
        x = int((seed_x + t * speed) % 1.0 * W)
        y = int((seed_y + math.sin(phase + n) * 0.08) % 1.0 * H)
        r = 1 + (n % 3)
        color = (255, 200, 60, 160) if n % 2 == 0 else (80, 255, 255, 170)
        draw.ellipse([x - r, y - r, x + r, y + r], fill=color)
        # soft halo
        draw.ellipse([x - r - 2, y - r - 2, x + r + 2, y + r + 2], outline=color)

    # Pulsing corner glows
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    pulse = int(50 + 40 * (math.sin(phase) * 0.5 + 0.5))
    gdraw.ellipse([-80, -60, 180, 160], fill=(255, 0, 180, pulse))
    gdraw.ellipse([W - 180, H - 140, W + 80, H + 60], fill=(0, 200, 255, pulse))
    glow = glow.filter(ImageFilter.GaussianBlur(28))
    overlay = Image.alpha_composite(overlay, glow)
    return overlay


def build() -> None:
    base = load_base()
    frames: list[Image.Image] = []

    for i in range(FRAMES):
        t = i / FRAMES
        # Base color / brightness breathe
        frame = ImageEnhance.Brightness(base).enhance(0.94 + 0.12 * (0.5 + 0.5 * math.sin(t * math.tau)))
        frame = ImageEnhance.Color(frame).enhance(1.05 + 0.18 * (0.5 + 0.5 * math.cos(t * math.tau)))
        frame_rgba = frame.convert("RGBA")

        overlay = neon_overlay(i, FRAMES)
        composed = Image.alpha_composite(frame_rgba, overlay)

        # Soft shimmer layer
        shimmer = ImageEnhance.Brightness(composed).enhance(1.04)
        shimmer = shimmer.filter(ImageFilter.GaussianBlur(0.8))
        composed = Image.blend(composed, shimmer, alpha=0.12 + 0.08 * abs(math.sin(t * math.tau)))

        # Convert for GIF
        frames.append(composed.convert("RGB").convert("P", palette=Image.ADAPTIVE, colors=192))

    frames[0].save(
        OUT,
        save_all=True,
        append_images=frames[1:],
        duration=DURATION_MS,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes, {FRAMES} frames)")


if __name__ == "__main__":
    build()
