from PIL import Image
from io import BytesIO

from PIL import ExifTags, Image, ImageChops, ImageStat
import pytesseract


ELA_RECOMPRESSION_QUALITY = 90
# Pixel differences above this value are counted as high-error ELA pixels.
ELA_HIGH_ERROR_THRESHOLD = 20
# This is a heuristic indicator, not a determination that an image was edited.
ELA_EDITING_INDICATOR_PERCENT = 1.0


def extract_text_from_image(image_path: str) -> str:
    """
    Extract text from an image using Tesseract OCR.
    """

    image = Image.open(image_path)

    text = pytesseract.image_to_string(image)

    return text.strip()


def extract_exif_metadata(image_data: bytes) -> dict:
    """Extract selected EXIF fields for informational purposes only."""

    allowed_tags = {
        "Make",
        "Model",
        "Software",
        "DateTime",
        "DateTimeOriginal",
        "Orientation",
    }

    with Image.open(BytesIO(image_data)) as image:
        exif = image.getexif()
        fields = {}

        for tag_id, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, tag_id)
            if tag_name in allowed_tags:
                fields[tag_name] = value

    return {
        "available": bool(fields),
        "fields": fields,
    }


def analyze_ela(image_data: bytes) -> dict:
    """Estimate JPEG recompression anomalies using a lightweight ELA heuristic."""

    with Image.open(BytesIO(image_data)) as original:
        if original.format not in {"JPEG", "JPG"}:
            return {
                "supported": False,
                "possible_editing_indicators": None,
                "reason": "ELA is currently limited to JPEG inputs",
            }

        original_rgb = original.convert("RGB")
        recompressed_buffer = BytesIO()
        original_rgb.save(
            recompressed_buffer,
            format="JPEG",
            quality=ELA_RECOMPRESSION_QUALITY,
        )
        recompressed_buffer.seek(0)

        with Image.open(recompressed_buffer) as recompressed:
            difference = ImageChops.difference(original_rgb, recompressed.convert("RGB"))
            difference_stat = ImageStat.Stat(difference)
            difference_luminance = difference.convert("L")
            high_error_mask = difference_luminance.point(
                lambda value: 255 if value >= ELA_HIGH_ERROR_THRESHOLD else 0
            )
            high_error_pixels = sum(
                count
                for value, count in enumerate(high_error_mask.histogram())
                if value > 0
            )
            total_pixels = difference.width * difference.height
            high_error_pixel_percent = (
                high_error_pixels / total_pixels * 100
                if total_pixels
                else 0.0
            )
            max_error = max(
                channel_max
                for _, channel_max in difference.getextrema()
            )

    return {
        "supported": True,
        "mean_error": round(sum(difference_stat.mean) / len(difference_stat.mean), 3),
        "max_error": max_error,
        "high_error_pixel_percent": round(high_error_pixel_percent, 3),
        "possible_editing_indicators": (
            high_error_pixel_percent >= ELA_EDITING_INDICATOR_PERCENT
        ),
    }


def analyze_image_forensics(image_data: bytes) -> dict:
    """Run EXIF and ELA independently so either result can degrade gracefully."""

    try:
        exif = extract_exif_metadata(image_data)
    except Exception as error:
        exif = {
            "available": False,
            "fields": {},
            "error": str(error),
        }

    try:
        ela = analyze_ela(image_data)
    except Exception as error:
        ela = {
            "supported": False,
            "possible_editing_indicators": None,
            "reason": str(error),
        }

    return {
        "exif": exif,
        "ela": ela,
    }