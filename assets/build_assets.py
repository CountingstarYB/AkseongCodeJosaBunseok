"""로고 원본(assets/src)을 축소·배경 제거해 HTML에 넣을 data URI로 만든다.

사용법: python assets/build_assets.py
결과: HTML 파일의 /*ASSETS-BEGIN*/ ~ /*ASSETS-END*/ 구간을 교체한다.
"""
import base64
import io
import pathlib

from PIL import Image, ImageDraw

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "src"
HTML = ROOT / "악성코드_조사분석_보고서_에이전트.html"


def white_to_alpha(img, lo=225, hi=250):
    """밝은 무채색 픽셀을 투명하게. lo~hi 구간은 부드럽게 처리."""
    img = img.convert("RGBA")
    px = img.load()
    w, h = img.size
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            m = min(r, g, b)
            if max(r, g, b) - m > 18:  # 유채색은 유지
                continue
            if m >= hi:
                px[x, y] = (r, g, b, 0)
            elif m > lo:
                px[x, y] = (r, g, b, int(a * (hi - m) / (hi - lo)))
    return img.crop(img.getbbox())


def outer_bg_to_alpha(img, thresh=60):
    """가장자리와 이어진 바깥 흰 배경만 투명하게(로고 안쪽 흰색은 유지)."""
    img = img.convert("RGBA")
    marker = img.convert("RGB")
    w, h = marker.size
    for xy in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1)):
        ImageDraw.floodfill(marker, xy, (255, 0, 255), thresh=thresh)
    mpx, px = marker.load(), img.load()
    for y in range(h):
        for x in range(w):
            if mpx[x, y] == (255, 0, 255):
                px[x, y] = (0, 0, 0, 0)
    return img.crop(img.getbbox())


def fit(img, width):
    h = round(img.height * width / img.width)
    return img.resize((width, h), Image.LANCZOS)


def data_uri(img):
    # PNG: 어떤 브라우저·뷰어에서도 표시되도록 가장 호환성 높은 형식 사용
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def main():
    cog = fit(outer_bg_to_alpha(Image.open(SRC / "cog.webp")), 192)
    slogan = fit(white_to_alpha(Image.open(SRC / "slogan.png"), 200, 245), 440)
    rokaf = fit(white_to_alpha(Image.open(SRC / "rokaf.png")), 420)
    for name, im in (("cog", cog), ("slogan", slogan), ("rokaf", rokaf)):
        im.save(ROOT / "assets" / f"logo_{name}.png", optimize=True)
    block = (
        "/*ASSETS-BEGIN*/\nconst ASSETS = {\n"
        f"  cog: '{data_uri(cog)}',\n"
        f"  slogan: '{data_uri(slogan)}',\n"
        f"  rokaf: '{data_uri(rokaf)}',\n"
        "};\n/*ASSETS-END*/"
    )
    html = HTML.read_text(encoding="utf-8")
    start = html.index("/*ASSETS-BEGIN*/")
    end = html.index("/*ASSETS-END*/") + len("/*ASSETS-END*/")
    HTML.write_text(html[:start] + block + html[end:], encoding="utf-8")
    print("ok", len(block), "chars")


if __name__ == "__main__":
    main()
