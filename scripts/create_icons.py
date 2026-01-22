from PIL import Image, ImageDraw, ImageFont
import os

def create_titan_icon(size):
    # Create transparent image
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Colors
    neon_blue = (0, 243, 255)
    neon_red = (255, 42, 109, 255)
    bg_color = (13, 17, 23, 255)
    
    # Draw Shield Background
    margin = size * 0.05
    points = [
        (size/2, margin),  # Top middle
        (size - margin, size * 0.3),  # Top right
        (size - margin, size * 0.6),  # Bottom right side
        (size/2, size - margin),  # Bottom tip
        (margin, size * 0.6),  # Bottom left side
        (margin, size * 0.3)   # Top left
    ]
    draw.polygon(points, fill=bg_color, outline=neon_blue, width=max(1, int(size*0.05)))
    
    # Draw "T" for Titan
    # Adjust coordinates for the T shape
    center_x = size / 2
    top_y = size * 0.25
    bottom_y = size * 0.75
    width = size * 0.4
    thickness = size * 0.1
    
    # T Top bar
    draw.rectangle(
        [center_x - width/2, top_y, center_x + width/2, top_y + thickness],
        fill=neon_red
    )
    # T Vertical bar
    draw.rectangle(
        [center_x - thickness/2, top_y, center_x + thickness/2, bottom_y],
        fill=neon_red
    )
    
    return img

def main():
    base_dir = r"d:\projects\degree\URL\url_sentinel\browser_extension\icons"
    os.makedirs(base_dir, exist_ok=True)
    
    sizes = [16, 48, 128]
    
    for size in sizes:
        try:
            img = create_titan_icon(size)
            path = os.path.join(base_dir, f"icon{size}.png")
            img.save(path)
            print(f"Created {path}")
        except Exception as e:
            print(f"Error creating icon size {size}: {e}")

if __name__ == "__main__":
    main()
