#!/usr/bin/env python3
"""Generate the extension's PNG icons (pure stdlib, no Pillow)."""
import math
import os
import struct
import zlib

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "icons")
SS = 4  # supersampling factor

BG = (23, 21, 50)
RING = (129, 140, 248)
DOT = (248, 113, 113)


def dist_to_segment(px, py, ax, ay, bx, by):
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    seg_len_sq = vx * vx + vy * vy
    t = 0.0 if seg_len_sq == 0 else max(0.0, min(1.0, (wx * vx + wy * vy) / seg_len_sq))
    cx, cy = ax + t * vx, ay + t * vy
    return math.hypot(px - cx, py - cy)


def render(size):
    w = size * SS
    margin = 0.035 * w
    radius = 0.22 * w
    left, top, right, bottom = margin, margin, w - margin, w - margin

    cx = cy = 0.43 * w
    ring_r = 0.255 * w
    ring_stroke = 0.095 * w
    dot_r = 0.075 * w

    hx1, hy1 = 0.585 * w, 0.585 * w
    hx2, hy2 = 0.80 * w, 0.80 * w
    handle_stroke = 0.095 * w

    hi = [[(0, 0, 0, 0)] * w for _ in range(w)]

    for y in range(w):
        py = y + 0.5
        for x in range(w):
            px = x + 0.5

            # rounded-rect background
            dx = max(left - px, px - right, 0.0)
            dy = max(top - py, py - bottom, 0.0)
            inside = math.hypot(dx, dy) <= radius and left <= px <= right and top <= py <= bottom
            if not inside:
                # corner arcs: inside if within radius of the nearest corner center
                ncx = min(max(px, left + radius), right - radius)
                ncy = min(max(py, top + radius), bottom - radius)
                inside = math.hypot(px - ncx, py - ncy) <= radius
            if not inside:
                continue

            r, g, b, a = BG[0], BG[1], BG[2], 255

            # magnifier ring
            if abs(math.hypot(px - cx, py - cy) - ring_r) <= ring_stroke / 2:
                r, g, b = RING
            # handle
            elif dist_to_segment(px, py, hx1, hy1, hx2, hy2) <= handle_stroke / 2:
                r, g, b = RING
            # center dot
            elif math.hypot(px - cx, py - cy) <= dot_r:
                r, g, b = DOT

            hi[y][x] = (r, g, b, a)

    # box-downsample
    out = [[(0, 0, 0, 0)] * size for _ in range(size)]
    area = SS * SS
    for y in range(size):
        for x in range(size):
            rs = gs = bs = als = 0
            for yy in range(SS):
                for xx in range(SS):
                    pr, pg, pb, pa = hi[y * SS + yy][x * SS + xx]
                    rs += pr * pa
                    gs += pg * pa
                    bs += pb * pa
                    als += pa
            if als == 0:
                out[y][x] = (0, 0, 0, 0)
            else:
                out[y][x] = (rs // als, gs // als, bs // als, als // area)
    return out


def write_png(path, pixels):
    size = len(pixels)
    raw = bytearray()
    for row in pixels:
        raw.append(0)  # filter type 0
        for r, g, b, a in row:
            raw.extend((r, g, b, a))

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as fh:
        fh.write(png)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for size in (16, 32, 48, 128):
        write_png(os.path.join(OUT_DIR, f"icon{size}.png"), render(size))
        print(f"wrote icons/icon{size}.png")


if __name__ == "__main__":
    main()
