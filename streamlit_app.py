import streamlit as st
import struct
from pathlib import Path
from datetime import datetime
import io

# --------------------------------------------------------------------
# STREAMLIT CONFIG (Must be first)
# --------------------------------------------------------------------
st.set_page_config(
    page_title="WD Head Map Editor",
    page_icon="💾",
    layout="wide"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        color: #666;
        margin-bottom: 2rem;
    }
    .head-active {
        color: green;
        font-weight: bold;
    }
    .head-inactive {
        color: red;
        font-weight: bold;
    }
    .hex-changed {
        background-color: #ffeb3b;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# --------------------------------------------------------------------
# PASSWORD PROTECTION
# --------------------------------------------------------------------
def check_password():
    """Returns `True` if the user had the correct password."""

    def password_entered():
        """Checks whether a password entered by the user is correct."""
        if st.session_state["password"] == st.secrets["password"]:
            st.session_state["password_correct"] = True
            del st.session_state["password"]  # Don't store password
        else:
            st.session_state["password_correct"] = False

    if "password_correct" not in st.session_state:
        # First run, show input for password
        st.markdown('<div class="main-header">🔐 WD Head Map Editor</div>', unsafe_allow_html=True)
        st.markdown('<div class="sub-header">Please enter password to continue</div>', unsafe_allow_html=True)
        st.text_input(
            "Password", type="password", on_change=password_entered, key="password"
        )
        return False
    elif not st.session_state["password_correct"]:
        # Password incorrect, show input + error
        st.markdown('<div class="main-header">🔐 WD Head Map Editor</div>', unsafe_allow_html=True)
        st.markdown('<div class="sub-header">Please enter password to continue</div>', unsafe_allow_html=True)
        st.text_input(
            "Password", type="password", on_change=password_entered, key="password"
        )
        st.error("😕 Password incorrect")
        return False
    else:
        # Password correct
        return True

# Check password before showing main app
if not check_password():
    st.stop()  # Stop execution if password is incorrect

# --------------------------------------------------------------------
# DRIVE CONFIGURATIONS
# --------------------------------------------------------------------
DRIVE_CONFIGS = {
    'SMR 10‑Head (WD50NMZM, etc.)': {
        'offset': 0x03E,
        'size': 2,
        'endian': 'little',
        'max_heads': 10
    },
    'Traditional 4‑Head (WD10JMVW, etc.)': {
        'offset': 0x23,
        'size': 1,
        'endian': 'little',
        'max_heads': 4
    },
    'SMR 8‑Head (WD40NMZW, etc.)': {
        'offset': 0x03E,
        'size': 2,
        'endian': 'little',
        'max_heads': 8
    },
    'Traditional 6‑Head (WD30EZRX, etc.)': {
        'offset': 0x23,
        'size': 1,
        'endian': 'little',
        'max_heads': 6
    },
    'Custom Offset': {
        'offset': 0x00,  # Will be set by user
        'size': 1,
        'endian': 'little',
        'max_heads': 10
    }
}

# Drive family prefixes
DRIVE_FAMILIES = {
    'N': 'Firebird / FB_USB',
    'Q': 'FB_Lite',
    'W': 'Standard WD',
}

# Known slider/preamp type mappings (4th character)
SLIDER_PREAMP_TYPES = {
    '7': 'M43.3B2 (Palmer)',
    'P': 'EC0C_R60',
    'Y': 'Type Y slider',
    'X': 'Type X slider',
    'R': 'Type R slider',
    'N': 'Type N slider',
    'K': 'Type K slider',
    'E': 'Type E slider',
    'C': 'Type C slider',
    'H': 'Type H slider',
    'D': 'Type D slider',
    '2': 'M16M.1 (Pebble Beach)',
    '3': 'M41.3A1 (Spyglass)',
    '6': 'M43.3B2 (Palmer)',
}

# --------------------------------------------------------------------
# CHECKSUM FUNCTIONS
# --------------------------------------------------------------------
def calculate_checksum(data, start=0x1E, end=0x3D, checksum_offset=0x3C):
    """Calculate sum-to-zero checksum for Module 0A (Traditional drives)"""
    # Sum all bytes in range EXCEPT the checksum byte itself
    total = sum(data[start:checksum_offset]) + sum(data[checksum_offset+1:end+1])
    # Calculate what value at checksum_offset makes sum = 0 (mod 256)
    checksum = (-total) & 0xFF
    return checksum

def update_checksum(data):
    """Update the checksum after modifications"""
    checksum = calculate_checksum(data)
    data[0x3C] = checksum
    return data

def verify_checksum(data):
    """Verify if current checksum is valid"""
    current_checksum = data[0x3C]
    calculated_checksum = calculate_checksum(data)
    return current_checksum == calculated_checksum

# --------------------------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------------------------
def read_head_map(data, cfg):
    """Read the head map value from Module 0A data."""
    offset, size = cfg['offset'], cfg['size']
    if offset + size > len(data):
        raise ValueError(f"Head map offset {offset} exceeds Module size")
    if size == 1:
        return data[offset]
    else:
        return struct.unpack('<H', data[offset:offset+2])[0]

def get_head_count(head_map):
    return head_map.bit_length() if head_map else 0

def get_active_heads(head_map, total):
    return [i for i in range(total) if head_map & (1 << i)]

def auto_detect_drive_type(file_data):
    """Try to auto-detect drive type from head map patterns"""
    for name, config in DRIVE_CONFIGS.items():
        if name == 'Custom Offset':
            continue
        try:
            head_map = read_head_map(file_data, config)
            head_count = get_head_count(head_map)
            
            if 2 <= head_count <= config['max_heads']:
                expected = (1 << head_count) - 1
                if head_map == expected or bin(head_map).count('1') >= head_count - 2:
                    return name
        except:
            continue
    return list(DRIVE_CONFIGS.keys())[0]

def validate_head_map(new_map):
    if new_map == 0:
        return False, "Cannot disable all heads! The drive requires at least one active head."
    return True, ""

# --------------------------------------------------------------------
# SLIDER CODE FUNCTIONS
# --------------------------------------------------------------------
def read_head_slider_code(data, offset=0x26, length=10):
    """Read the head slider code from Module 0A at offset 0x26"""
    try:
        code_bytes = data[offset:offset+length]
        code = code_bytes.decode('ascii', errors='ignore').strip('\x00')
        # Validate it looks like a slider code
        if code.startswith('|') and '|' in code[1:]:
            return code
        return None
    except:
        return None


def parse_slider_info(slider_code):
    """
    Parse slider type and drive family from head slider code.
    
    Format examples:
      |Q|HJ Y JBHS  → Family: Q (FB_Lite), Slider: Y (4th char)
      |N|CS R QDCS  → Family: N (Firebird), Slider: R (4th char)
      |W|2ZECH2F    → Family: W (Standard), Slider: E (4th char)
    
    The 4th character (ignoring pipes and spaces) indicates slider type.
    Slider type must match for optimal R/W compatibility.
    """
    if not slider_code:
        return None, None, None, None
    
    # Extract family prefix (first character after first |)
    family_char = None
    if slider_code.startswith('|') and len(slider_code) > 2:
        family_char = slider_code[1]
    
    family_name = DRIVE_FAMILIES.get(family_char, 'Unknown')
    
    # Remove all pipes and spaces to get clean character sequence
    clean_code = slider_code.replace('|', '').replace(' ', '')
    
    # 4th character is the slider type
    slider_char = None
    preamp_type = None
    
    if len(clean_code) >= 4:
        slider_char = clean_code[3]  # 4th character (0-indexed = 3)
        preamp_type = SLIDER_PREAMP_TYPES.get(slider_char, f'Type {slider_char} slider')
    
    return family_char, family_name, slider_char, preamp_type

# --------------------------------------------------------------------
# HEX VIEWER FUNCTIONS
# --------------------------------------------------------------------
def generate_hex_view(data, highlight_ranges=None, bytes_per_row=16):
    """
    Generate hex dump with optional highlighting.
    highlight_ranges: list of (start, end) tuples to highlight
    """
    lines = []
    for i in range(0, len(data), bytes_per_row):
        # Offset
        offset = f"{i:04X}"
        
        # Hex bytes
        hex_bytes = []
        ascii_chars = []
        
        for j in range(bytes_per_row):
            if i + j < len(data):
                byte = data[i + j]
                
                # Check if this byte should be highlighted
                is_highlighted = False
                if highlight_ranges:
                    for start, end in highlight_ranges:
                        if start <= i + j < end:
                            is_highlighted = True
                            break
                
                if is_highlighted:
                    hex_bytes.append(f"[{byte:02X}]")
                else:
                    hex_bytes.append(f"{byte:02X}")
                
                # ASCII representation
                if 32 <= byte < 127:
                    ascii_chars.append(chr(byte))
                else:
                    ascii_chars.append('.')
            else:
                hex_bytes.append("  ")
                ascii_chars.append(" ")
        
        hex_str = " ".join(hex_bytes)
        ascii_str = "".join(ascii_chars)
        lines.append(f"{offset}  {hex_str}  |{ascii_str}|")
    
    return "\n".join(lines)

# --------------------------------------------------------------------
# MAIN APP (Only shows if password correct)
# --------------------------------------------------------------------

# Header
st.markdown('<div class="main-header">💾 WD Head Map Editor</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Edit Module 0A head maps for Western Digital hard drives</div>', unsafe_allow_html=True)

# Initialize session state
if 'file_data' not in st.session_state:
    st.session_state.file_data = None
if 'file_name' not in st.session_state:
    st.session_state.file_name = None
if 'heads_to_toggle' not in st.session_state:
    st.session_state.heads_to_toggle = []
if 'custom_offset' not in st.session_state:
    st.session_state.custom_offset = 0x3E
if 'custom_size' not in st.session_state:
    st.session_state.custom_size = 2
if 'custom_max_heads' not in st.session_state:
    st.session_state.custom_max_heads = 10

# --------------------------------------------------------------------
# 1. FILE UPLOAD
# --------------------------------------------------------------------
st.markdown("### 1️⃣ Load Module 0A")
uploaded_file = st.file_uploader(
    "Upload your Module 0A file (.0a or .bin)",
    type=['0a', 'bin'],
    help="Select the Module 0A file extracted from your WD hard drive ROM"
)

if uploaded_file is not None:
    st.session_state.file_data = bytearray(uploaded_file.read())
    st.session_state.file_name = uploaded_file.name
    
    file_size = len(st.session_state.file_data)
    
    # Validation
    if file_size < 256:
        st.warning("⚠️ File is very small for a Module 0A. Are you sure this is the correct file?")
    elif file_size > 16384:
        st.warning("⚠️ File seems large for a Module 0A. This might be a full ROM. Please extract Module 0A first.")
    else:
        st.success(f"✅ Loaded: **{st.session_state.file_name}** ({file_size:,} bytes)")

# --------------------------------------------------------------------
# 2. SLIDER CODE INFO (Show early for reference)
# --------------------------------------------------------------------
if st.session_state.file_data is not None:
    st.markdown("---")
    st.markdown("### 2️⃣ Head Slider Information")

    slider_code = read_head_slider_code(st.session_state.file_data)

    if slider_code:
        family_char, family_name, slider_char, preamp_type = parse_slider_info(slider_code)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Slider Code", slider_code)
        
        with col2:
            if family_char:
                st.metric("Drive Family", f"|{family_char}|", help=family_name)
            else:
                st.metric("Drive Family", "Unknown")
        
        with col3:
            if slider_char:
                st.metric("Slider Type", f"Type {slider_char}", 
                         help="4th character - must match for R/W compatibility")
            else:
                st.metric("Slider Type", "Unknown")
        
        with col4:
            if preamp_type:
                st.metric("Preamp/Slider", preamp_type)
            else:
                st.metric("Preamp/Slider", "Not identified")
        
        # Important warning
        st.info("⚠️ **Slider Compatibility**: For optimal read/write compatibility, donor heads must have the **same slider type** (4th character must match).")
        
        # Detailed info
        with st.expander("📋 Detailed Slider Code Analysis"):
            clean_code = slider_code.replace('|', '').replace(' ', '')
            
            # Show character breakdown
            st.markdown("**Character Breakdown** (ignoring pipes and spaces):")
            char_table = "| Position | Character | Meaning |\n|:---|:---:|:---|\n"
            meanings = ["Drive Family", "Code Char 1", "Code Char 2", "**SLIDER TYPE**", 
                       "Code Char 4", "Code Char 5", "Code Char 6", "Code Char 7"]
            
            for i, char in enumerate(clean_code[:8]):
                meaning = meanings[i] if i < len(meanings) else "Code char"
                char_table += f"| {i+1} | **{char}** | {meaning} |\n"
            
            st.markdown(char_table)
            
            st.code(f"""
Original Code: {slider_code}
Clean Code:    {clean_code}

Drive Family:  |{family_char}| = {family_name}
Slider Type:   {slider_char} (4th character)
Preamp/Slider: {preamp_type}

Code Location: Offset 0x26 in Module 0A
Full ROM Address: 0x0007C020

Known Slider Type Mappings:
7 → M43.3B2 (Palmer)
P → EC0C_R60
E → Type E slider
D → Type D slider (possibly M43.3B2)
M → Type M slider
2 → M16M.1 (Pebble Beach)
3 → M41.3A1 (Spyglass)
6 → M43.3B2 (Palmer)
""")

            
        # Show hex dump
        slider_bytes = st.session_state.file_data[0x26:0x26+10]
        hex_str = ' '.join([f'{b:02X}' for b in slider_bytes])
        ascii_str = ''.join([chr(b) if 32 <= b < 127 else '.' for b in slider_bytes])
        st.code(f"Offset 0x26 (hex):\n{hex_str}\n\nASCII:\n{ascii_str}")
            
        # Compatibility checker
        with st.expander("🔍 Donor Compatibility Checker"):
            st.markdown("Enter a donor drive's slider code to check compatibility:")
            donor_code = st.text_input("Donor Slider Code", placeholder="|W|2ZECH2F")
            
            if donor_code:
                _, _, donor_slider, _ = parse_slider_info(donor_code)
                
                if donor_slider and slider_char:
                    if donor_slider == slider_char:
                        st.success(f"✅ **COMPATIBLE** - Both drives use Type {slider_char} slider")
                    else:
                        st.error(f"❌ **NOT COMPATIBLE** - Original: Type {slider_char}, Donor: Type {donor_slider}")
                        st.warning("Using mismatched sliders may result in poor R/W performance!")
                else:
                    st.warning("Could not parse slider type from one or both codes")
                    
    else:
        st.warning("⚠️ Could not read head slider code from Module 0A")

# --------------------------------------------------------------------
# 3. DRIVE TYPE SELECTION
# --------------------------------------------------------------------
if st.session_state.file_data is not None:
    st.markdown("---")
    st.markdown("### 3️⃣ Select Drive Type (if auto-detect is wrong)")
    
    # Auto-detect
    detected_type = auto_detect_drive_type(st.session_state.file_data)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        drive_type = st.selectbox(
            "Drive Family",
            options=list(DRIVE_CONFIGS.keys()),
            index=list(DRIVE_CONFIGS.keys()).index(detected_type),
            help="Select your drive family or let auto-detection choose"
        )
    with col2:
        if st.button("🔍 Auto-Detect", use_container_width=True):
            st.rerun()
    
    config = DRIVE_CONFIGS[drive_type].copy()
    
    # Custom offset option
    if drive_type == 'Custom Offset':
        st.markdown("#### Custom Configuration")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            custom_offset_hex = st.text_input(
                "Head Map Offset (hex)", 
                value=f"0x{st.session_state.custom_offset:02X}",
                help="Enter offset in hex format (e.g., 0x3E)"
            )
            try:
                st.session_state.custom_offset = int(custom_offset_hex, 16)
                config['offset'] = st.session_state.custom_offset
            except:
                st.error("Invalid hex value")
        
        with col2:
            st.session_state.custom_size = st.selectbox(
                "Field Size (bytes)",
                options=[1, 2],
                index=1 if st.session_state.custom_size == 2 else 0
            )
            config['size'] = st.session_state.custom_size
        
        with col3:
            st.session_state.custom_max_heads = st.number_input(
                "Max Heads",
                min_value=1,
                max_value=16,
                value=st.session_state.custom_max_heads
            )
            config['max_heads'] = st.session_state.custom_max_heads
    else:
        # Show current config
        with st.expander("ℹ️ Drive Configuration Details"):
            st.code(f"""
Drive Type: {drive_type}
Head Map Offset: 0x{config['offset']:04X}
Field Size: {config['size']} byte(s)
Max Heads: {config['max_heads']}
            """)
    
    # --------------------------------------------------------------------
    # 4. CURRENT HEAD MAP
    # --------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 4️⃣ Current Head Map")
    
    try:
        original_head_map = read_head_map(st.session_state.file_data, config)
        total_heads = get_head_count(original_head_map)
        active_heads = get_active_heads(original_head_map, total_heads)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Heads", total_heads)
        with col2:
            st.metric("Active Heads", len(active_heads))
        with col3:
            st.metric("Head Map Value", f"0x{original_head_map:04X}")
        
        # Checksum info for traditional drives
        if config['offset'] == 0x23:  # Traditional drive
            checksum_valid = verify_checksum(st.session_state.file_data)
            current_checksum = st.session_state.file_data[0x3C]
            
            st.info(f"📋 **Traditional Drive Detected** - Checksum at 0x3C: 0x{current_checksum:02X} {'✅ Valid' if checksum_valid else '⚠️ Invalid'}")
        
        with st.expander("📊 View Detailed Head Map Info"):
            st.code(f"""
Head Map Value: 0x{original_head_map:04X}
Binary: {bin(original_head_map)}
Active Heads: {active_heads}
Head Map Offset: 0x{config['offset']:04X}
Field Size: {config['size']} byte(s)
            """)
        
        # --------------------------------------------------------------------
        # 5. HEAD SELECTION
        # --------------------------------------------------------------------
        st.markdown("---")
        st.markdown("### 5️⃣ Toggle Heads (Enable/Disable)")
        st.info("💡 Check heads to **toggle** their state. Active heads will be disabled, inactive heads will be enabled.")
        
        # Create checkboxes in columns
        cols_layout = st.columns(5)
        selected_heads = []
        
        for i in range(total_heads):
            with cols_layout[i % 5]:
                is_active = i in active_heads
                status = "✅ Active" if is_active else "❌ Inactive"
                
                if st.checkbox(
                    f"Head {i}",
                    key=f"head_{i}",
                    help=f"Current status: {status}"
                ):
                    selected_heads.append(i)
                
                # Show status
                if is_active:
                    st.markdown(f'<span class="head-active">{status}</span>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<span class="head-inactive">{status}</span>', unsafe_allow_html=True)
        
        # Clear All button
        if st.button("🔄 Clear All Selections"):
            for i in range(total_heads):
                st.session_state[f"head_{i}"] = False
            st.rerun()
        
        # --------------------------------------------------------------------
        # 6. PREVIEW
        # --------------------------------------------------------------------
        if selected_heads:
            st.markdown("---")
            st.markdown("### 6️⃣ Preview Changes")
            
            # Calculate new head map
            new_map = original_head_map
            for h in selected_heads:
                new_map ^= (1 << h)
            
            # Validate
            is_valid, error_msg = validate_head_map(new_map)
            
            if not is_valid:
                st.error(f"❌ {error_msg}")
            else:
                new_active = get_active_heads(new_map, total_heads)
                new_disabled = sorted(set(range(total_heads)) - set(new_active))
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**📌 Original Head Map**")
                    st.code(f"""
Value: 0x{original_head_map:04X}
Binary: {bin(original_head_map)}
Active: {active_heads}
                    """)
                
                with col2:
                    st.markdown("**🔄 New Head Map**")
                    st.code(f"""
Value: 0x{new_map:04X}
Binary: {bin(new_map)}
Active: {new_active}
Disabled: {new_disabled}
                    """)
                
                # Changes summary
                st.markdown("**📝 Changes Summary**")
                for h in selected_heads:
                    if h in active_heads:
                        st.markdown(f"- Head {h}: **Active** → **DISABLED** ❌")
                    else:
                        st.markdown(f"- Head {h}: **Inactive** → **ENABLED** ✅")
                
                # Checksum option for traditional drives
                update_checksum_option = False
                if config['offset'] == 0x23:  # Traditional drive
                    st.markdown("---")
                    st.markdown("#### Checksum Options")
                    update_checksum_option = st.checkbox(
                        "Update checksum after modification (Traditional drives only)",
                        value=False,
                        help="Checksum at 0x3C covers 0x1E-0x3D. Enable this if you experience issues with the modified module."
                    )
                    
                    if update_checksum_option:
                        st.info("✅ Checksum will be recalculated and updated at offset 0x3C")
                    else:
                        st.warning("⚠️ Checksum will NOT be updated (default). Enable if drive rejects the module.")
                
                # Byte changes
                with st.expander("🔍 View Byte-Level Changes"):
                    offset, size = config['offset'], config['size']
                    if size == 1:
                        st.code(f"""
Offset 0x{offset:04X}:
  Before: 0x{original_head_map:02X}
  After:  0x{new_map:02X}
                        """)
                    else:
                        old_bytes = struct.pack('<H', original_head_map)
                        new_bytes = struct.pack('<H', new_map)
                        st.code(f"""
Offset 0x{offset:04X}-0x{offset+1:04X}:
  Before: {old_bytes.hex().upper()} ({old_bytes[0]:02X} {old_bytes[1]:02X})
  After:  {new_bytes.hex().upper()} ({new_bytes[0]:02X} {new_bytes[1]:02X})
                        """)
                    
                    if update_checksum_option:
                        # Show checksum change
                        old_checksum = st.session_state.file_data[0x3C]
                        
                        # Calculate new checksum
                        temp_data = bytearray(st.session_state.file_data)
                        temp_data[offset] = new_map & 0xFF
                        new_checksum = calculate_checksum(temp_data)
                        
                        st.code(f"""
Checksum at 0x3C:
  Before: 0x{old_checksum:02X}
  After:  0x{new_checksum:02X}
                        """)
                
                # --------------------------------------------------------------------
                # 7. HEX VIEWER
                # --------------------------------------------------------------------
                with st.expander("🔬 Hex Viewer - Compare Original vs Modified"):
                    # Create modified data for preview
                    preview_data = bytearray(st.session_state.file_data)
                    offset, size = config['offset'], config['size']
                    
                    if size == 1:
                        preview_data[offset] = new_map & 0xFF
                    else:
                        preview_data[offset:offset+2] = struct.pack('<H', new_map)
                    
                    # Update checksum if requested
                    if update_checksum_option:
                        preview_data = update_checksum(preview_data)
                    
                    # Determine highlight ranges
                    highlight_ranges = [(offset, offset + size)]
                    if update_checksum_option:
                        highlight_ranges.append((0x3C, 0x3D))
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Original Data**")
                        # Show relevant section (around the changed bytes)
                        start_view = max(0, (offset // 16) * 16 - 32)
                        end_view = min(len(st.session_state.file_data), ((offset + size) // 16 + 3) * 16)
                        
                        hex_view_original = generate_hex_view(
                            st.session_state.file_data[start_view:end_view],
                            highlight_ranges=[(offset - start_view, offset - start_view + size)],
                        )
                        st.code(hex_view_original, language="")
                    
                    with col2:
                        st.markdown("**Modified Data** ([] = changed bytes)")
                        hex_view_modified = generate_hex_view(
                            preview_data[start_view:end_view],
                            highlight_ranges=[(r[0] - start_view, r[1] - start_view) for r in highlight_ranges],
                        )
                        st.code(hex_view_modified, language="")
                    
                    st.caption("Note: Changed bytes are shown in [brackets]")
                
                # --------------------------------------------------------------------
                # 8. SAVE
                # --------------------------------------------------------------------
                st.markdown("---")
                st.markdown("### 7️⃣ Download Files")
                
                # Create modified file data
                mod_data = bytearray(st.session_state.file_data)
                offset, size = config['offset'], config['size']
                if size == 1:
                    mod_data[offset] = new_map & 0xFF
                else:
                    mod_data[offset:offset+2] = struct.pack('<H', new_map)
                
                # Update checksum if requested
                if update_checksum_option:
                    mod_data = update_checksum(mod_data)
                
                # Determine output filename with descriptive naming
                original_stem = Path(st.session_state.file_name).stem
                
                # Build descriptive filename based on changes
                disabled_heads = [h for h in selected_heads if h in active_heads]
                enabled_heads = [h for h in selected_heads if h not in active_heads]
                
                # Create filename suffix
                suffix_parts = []
                if disabled_heads:
                    heads_str = "_".join([f"H{h}" for h in disabled_heads])
                    suffix_parts.append(f"{heads_str}_off")
                if enabled_heads:
                    heads_str = "_".join([f"H{h}" for h in enabled_heads])
                    suffix_parts.append(f"{heads_str}_on")
                
                filename_suffix = "_".join(suffix_parts)
                output_filename = f"{original_stem}_{filename_suffix}.bin"
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.download_button(
                        label="💾 Download Modified Module 0A",
                        data=bytes(mod_data),
                        file_name=output_filename,
                        mime="application/octet-stream",
                        use_container_width=True
                    )
                
                with col2:
                    # Generate report
                    report = f"""WD Head Map Modification Report
{'=' * 50}

Original File: {st.session_state.file_name}
Output File: {output_filename}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Drive Type: {drive_type}

Head Slider Code: {slider_code if slider_code else 'N/A'}
Slider Type: {slider_char if slider_char else 'N/A'}
Preamp: {preamp_type if preamp_type else 'N/A'}

Original Head Map: 0x{original_head_map:04X}
New Head Map: 0x{new_map:04X}

Toggled Heads: {selected_heads}

Changes Summary:
"""
                    for h in selected_heads:
                        if h in active_heads:
                            report += f"Head {h}: Active → DISABLED\n"
                        else:
                            report += f"Head {h}: Inactive → ENABLED\n"
                    
                    if update_checksum_option:
                        report += f"\nChecksum updated: YES (0x{mod_data[0x3C]:02X})\n"
                    else:
                        report += f"\nChecksum updated: NO\n"
                    
                    report_filename = f"{original_stem}_{filename_suffix}_report.txt"
                    
                    st.download_button(
                        label="📄 Download Report",
                        data=report,
                        file_name=report_filename,
                        mime="text/plain",
                        use_container_width=True
                    )
                
                st.success(f"✅ Ready to download: **{output_filename}**")
        
        else:
            st.info("👆 Select heads to toggle above to preview changes")
    
    except Exception as e:
        st.error(f"❌ Error parsing head map: {str(e)}")

else:
    st.info("👆 Upload a Module 0A file to get started")

# --------------------------------------------------------------------
# FOOTER
# --------------------------------------------------------------------
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; padding: 2rem;'>
    <p><strong>⚠️ For data recovery professionals only. Use at your own risk.</strong></p>
    <p>Remember to physically cut damaged heads before editing the head map.</p>
    <p>Made with ❤️ for efficiency | v2.0</p>
</div>
""", unsafe_allow_html=True)

# --------------------------------------------------------------------
# HELP SIDEBAR
# --------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 📖 Help Guide")
    st.markdown("""
    ### How to Use
    
    1. **Upload** your Module 0A file
    2. **Check slider type** for donor compatibility
    3. **Select** your drive type (auto-detected)
    4. **Review** current head map
    5. **Toggle** heads you want to enable/disable
    6. **Preview** changes in hex viewer
    7. **Download** modified file & report
    
    ### Slider Type (4th Character)

    The **4th character** in the slider code identifies the slider type:
    - Must **match exactly** for donor compatibility
    - Found at offset 0x26 in Module 0A    # ← Fixed!

    
    **Format**: `|X|YY Z SSSS`
    - X = Drive family (N, Q, W)
    - YY = Code prefix
    - **Z = Slider type** ← Must match!
    - SSSS = Additional code
    
    **Examples**:
    - `|Q|HJ Y JBHS` → Type **Y** slider
    - `|N|CS R QDCS` → Type **R** slider  
    - `|W|2ZECH2F` → Type **E** slider
    
    ### Drive Families
    
    - **|N|** = Firebird / FB_USB
    - **|Q|** = FB_Lite
    - **|W|** = Standard WD drives
    
    ### Checksum (Traditional Drives)
    
    Traditional drives (offset 0x23) use a checksum at 0x3C:
    - Covers bytes 0x1E through 0x3D
    - Sum-to-zero algorithm
    - **Usually not needed** (leave unchecked)
    - Enable if drive rejects the module
    
    ### Custom Offset
    
    For unknown drive types:
    - Select "Custom Offset" from drive type
    - Enter head map location in hex (e.g., 0x3E)
    - Specify field size (1 or 2 bytes)
    - Set maximum number of heads
    
    ### Tips
    
    - At least one head must remain active
    - Slider types must match for optimal R/W
    - Original file is never modified
    - Use hex viewer to verify changes
    - Filenames show which heads were changed
    - Check slider code before sourcing donors
    """)
