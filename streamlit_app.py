import streamlit as st
import struct
from pathlib import Path
from datetime import datetime, timedelta
import hashlib
import io
import extra_streamlit_components as stx

# --------------------------------------------------------------------
# STREAMLIT CONFIG (Must be first)
# --------------------------------------------------------------------
st.set_page_config(
    page_title="WD Head Map Editor",
    page_icon="💾",
    layout="wide"
)

# Custom CSS
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
# COOKIE MANAGER (Initialize once)
# --------------------------------------------------------------------
cookie_manager = stx.CookieManager()

# --------------------------------------------------------------------
# PASSWORD PROTECTION WITH COOKIE PERSISTENCE
# --------------------------------------------------------------------
def hash_password(password):
    """Create a hash of the password for cookie storage"""
    salt = st.secrets.get("salt", "default_salt_change_me_12345")
    return hashlib.sha256((password + salt).encode()).hexdigest()

def check_password():
    """Returns `True` if the user had the correct password."""

    def password_entered():
        """Checks whether a password entered by the user is correct."""
        if st.session_state["password"] == st.secrets["password"]:
            st.session_state["password_correct"] = True
            
            # If remember me is checked, set cookie
            if st.session_state.get("remember_me", False):
                token = hash_password(st.secrets["password"])
                cookie_manager.set("wd_auth_token", token, expires_at=datetime.now() + timedelta(days=30))
                st.success("✅ You will be remembered on this device for 30 days")
            
            del st.session_state["password"]
        else:
            st.session_state["password_correct"] = False

    # Check for existing valid cookie (auto-login)
    if "password_correct" not in st.session_state:
        cookies = cookie_manager.get_all()
        
        if cookies and "wd_auth_token" in cookies:
            token = cookies.get("wd_auth_token")
            expected_token = hash_password(st.secrets["password"])
            
            if token == expected_token:
                st.session_state["password_correct"] = True
                return True

    if "password_correct" not in st.session_state:
        # First run, show input for password
        st.markdown('<div class="main-header">🔐 WD Head Map Editor</div>', unsafe_allow_html=True)
        st.markdown('<div class="sub-header">Please enter password to continue</div>', unsafe_allow_html=True)
        
        st.text_input(
            "Password", type="password", on_change=password_entered, key="password"
        )
        st.checkbox("Remember me on this device (30 days)", key="remember_me", 
                   help="Save login credentials securely in browser for 30 days")
        
        return False
    elif not st.session_state["password_correct"]:
        # Password incorrect
        st.markdown('<div class="main-header">🔐 WD Head Map Editor</div>', unsafe_allow_html=True)
        st.markdown('<div class="sub-header">Please enter password to continue</div>', unsafe_allow_html=True)
        
        st.text_input(
            "Password", type="password", on_change=password_entered, key="password"
        )
        st.checkbox("Remember me on this device (30 days)", key="remember_me")
        
        st.error("😕 Password incorrect")
        return False
    else:
        # Password correct - show logout option in sidebar
        return True

if not check_password():
    st.stop()

# Add logout button in sidebar after successful login
with st.sidebar:
    if st.button("🚪 Logout", use_container_width=True):
        # Clear session
        st.session_state["password_correct"] = False
        # Delete cookie
        cookie_manager.delete("wd_auth_token")
        st.rerun()

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
        'offset': 0x00,
        'size': 1,
        'endian': 'little',
        'max_heads': 10
    }
}

DRIVE_FAMILIES = {
    'N': 'Firebird / FB_USB',
    'Q': 'FB_Lite',
    'W': 'Standard WD',
}

# HSA/Slider type mappings - 4th character (excluding pipes) = HSA type
SLIDER_PREAMP_TYPES = {
    '7': 'M43.3B2 (Palmer)',
    '6': 'M43.3B2 (Palmer)',
    '3': 'M41.3A1 & 314 (Spyglass)',
    '2': 'M16M.1 (Pebble Beach)',
    '5': 'M16M.1/M16M.2 (Pebble Beach)',
    'P': 'EC0C_R60',
    'Y': 'Type Y HSA',
    'X': 'Type X HSA',
    'R': 'Type R HSA',
    'N': 'Type N HSA',
    'K': 'Type K HSA',
    'E': 'Type E HSA',
    'C': 'Type C HSA',
    'H': 'Type H HSA',
    'D': 'Type D HSA',
    'M': 'Type M HSA',
}

def get_head_family(hsa_char):
    """Identify head family from HSA character"""
    family_map = {
        'Pebble Beach': ['2', '5'],
        'Spyglass': ['3'],
        'Palmer': ['6', '7'],
    }
    for family, chars in family_map.items():
        if hsa_char in chars:
            return family
    return None

# --------------------------------------------------------------------
# CHECKSUM FUNCTIONS
# --------------------------------------------------------------------
def calculate_checksum(data, start=0x1E, end=0x3D, checksum_offset=0x3C):
    total = sum(data[start:checksum_offset]) + sum(data[checksum_offset+1:end+1])
    checksum = (-total) & 0xFF
    return checksum

def update_checksum(data):
    checksum = calculate_checksum(data)
    data[0x3C] = checksum
    return data

def verify_checksum(data):
    current_checksum = data[0x3C]
    calculated_checksum = calculate_checksum(data)
    return current_checksum == calculated_checksum

# --------------------------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------------------------
def read_head_map(data, cfg):
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
# DCM/SLIDER CODE FUNCTIONS
# --------------------------------------------------------------------
def read_head_slider_code(data, offset=0x26, length=10):
    """Read the head slider code from Module 0A at offset 0x26"""
    try:
        code_bytes = data[offset:offset+length]
        code = code_bytes.decode('ascii', errors='ignore').strip('\x00')
        if code.startswith('|') and '|' in code[1:]:
            return code
        return None
    except:
        return None

def parse_dcm_details(slider_code):
    """
    Parse full DCM structure.
    THE HSA IS AT POSITION 4 (excluding pipes), NOT POSITION 7!
    
    Correct positions (excluding pipes):
    1. Drive Family (N, Q, W)
    2. Spindle Motor
    3. Base
    4. HSA (Head Stack Assembly / Slider Type) ← Position 4!
    5. Latch
    6. Preamp
    7. Media
    8. Bottom VCM
    9. ACA (Arm Coil Assembly)
    10. Top VCM
    """
    if not slider_code:
        return None
    
    clean_code = slider_code.replace('|', '').replace(' ', '')
    
    dcm_info = {
        'family': clean_code[0] if len(clean_code) > 0 else None,
        'spindle_motor': clean_code[1] if len(clean_code) > 1 else None,
        'base': clean_code[2] if len(clean_code) > 2 else None,
        'hsa': clean_code[3] if len(clean_code) > 3 else None,  # POSITION 4 = HSA!
        'latch': clean_code[4] if len(clean_code) > 4 else None,
        'preamp': clean_code[5] if len(clean_code) > 5 else None,
        'media': clean_code[6] if len(clean_code) > 6 else None,
        'bottom_vcm': clean_code[7] if len(clean_code) > 7 else None,
        'aca': clean_code[8] if len(clean_code) > 8 else None,
        'top_vcm': clean_code[9] if len(clean_code) > 9 else None,
    }
    
    return dcm_info


def parse_slider_info(slider_code):
    """Parse HSA (slider type) and drive family from code."""
    if not slider_code:
        return None, None, None, None
    
    family_char = None
    if slider_code.startswith('|') and len(slider_code) > 2:
        family_char = slider_code[1]
    
    family_name = DRIVE_FAMILIES.get(family_char, 'Unknown')
    clean_code = slider_code.replace('|', '').replace(' ', '')
    
    # Position 4 (index 3) when excluding pipes = HSA type (slider type)
    hsa_char = None
    hsa_type = None
    
    if len(clean_code) >= 4:
        hsa_char = clean_code[3]  # 4th character = HSA
        hsa_type = SLIDER_PREAMP_TYPES.get(hsa_char, f'Type {hsa_char} HSA')
    
    return family_char, family_name, hsa_char, hsa_type

# --------------------------------------------------------------------
# HEX VIEWER FUNCTIONS
# --------------------------------------------------------------------
def generate_hex_view(data, highlight_ranges=None, bytes_per_row=16):
    lines = []
    for i in range(0, len(data), bytes_per_row):
        offset = f"{i:04X}"
        hex_bytes = []
        ascii_chars = []
        
        for j in range(bytes_per_row):
            if i + j < len(data):
                byte = data[i + j]
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
# MAIN APP
# --------------------------------------------------------------------
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
    
    if file_size < 256:
        st.warning("⚠️ File is very small for a Module 0A. Are you sure this is the correct file?")
    elif file_size > 16384:
        st.warning("⚠️ File seems large for a Module 0A. This might be a full ROM. Please extract Module 0A first.")
    else:
        st.success(f"✅ Loaded: **{st.session_state.file_name}** ({file_size:,} bytes)")

# --------------------------------------------------------------------
# 2. DCM / SLIDER CODE INFO
# --------------------------------------------------------------------
if st.session_state.file_data is not None:
    st.markdown("---")
    st.markdown("### 2️⃣ DCM / Head Slider Information")

    slider_code = read_head_slider_code(st.session_state.file_data)

    if slider_code:
        family_char, family_name, hsa_char, hsa_type = parse_slider_info(slider_code)
        head_family = get_head_family(hsa_char)
        dcm = parse_dcm_details(slider_code)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("DCM Code", slider_code)
        
        with col2:
            if family_char:
                st.metric("Drive Family", f"|{family_char}|", help=family_name)
            else:
                st.metric("Drive Family", "Unknown")
        
        with col3:
            if hsa_char:
                st.metric("HSA (Slider Type)", f"Type {hsa_char}", 
                         help="4th character (HSA) - must match for R/W compatibility")
            else:
                st.metric("HSA (Slider Type)", "Unknown")
        
        with col4:
            if head_family:
                emoji_map = {'Pebble Beach': '🏖️', 'Spyglass': '🔭', 'Palmer': '🌴'}
                st.metric("Head Family", 
                         f"{emoji_map.get(head_family, '📌')} {head_family}",
                         help="Donor heads must match this family")
            elif hsa_type:
                st.metric("Preamp", hsa_type)
            else:
                st.metric("Preamp", "Not identified")
        
        st.info("⚠️ **HSA Compatibility**: For optimal read/write compatibility, donor heads must have the **same HSA type** (4th character must match).")
        
        # Detailed DCM breakdown
        with st.expander("📋 Detailed DCM Structure Analysis"):
            clean_code = slider_code.replace('|', '').replace(' ', '')
            
            st.markdown("### DCM (Drive Configuration Management) Breakdown")
            st.markdown("""
The DCM code encodes physical drive components where each position identifies a specific part.
            """)
            
            dcm_table = f"""
| Position | Character | Component | Value | Priority |
|:---------|:---------:|:----------|:------|:---------|
| 1 | **{dcm['family'] or '?'}** | Drive Family | &#124;{dcm['family'] or '?'}&#124; ({family_name}) | ℹ️ Info |
| 2 | **{dcm['spindle_motor'] or '?'}** | Spindle Motor | {dcm['spindle_motor'] or '?'} | 🟡 Low |
| 3 | **{dcm['base'] or '?'}** | Base | {dcm['base'] or '?'} | 🟡 Low |
| 4 | **{dcm['hsa'] or '?'}** | **HSA (Slider)** | **{hsa_type or 'Unknown'}** | 🔴 **CRITICAL** |
| 5 | **{dcm['latch'] or '?'}** | Latch | {dcm['latch'] or '?'} | 🟡 Low |
| 6 | **{dcm['preamp'] or '?'}** | Preamp | {dcm['preamp'] or '?'} | 🟠 High |
| 7 | **{dcm['media'] or '?'}** | Media Type | {dcm['media'] or '?'} | 🟠 High |
| 8 | **{dcm['bottom_vcm'] or '?'}** | Bottom VCM | {dcm['bottom_vcm'] or '?'} | 🟠 High |
| 9 | **{dcm['aca'] or '?'}** | ACA | {dcm['aca'] or '?'} | 🟠 High |
| 10 | **{dcm['top_vcm'] or '?'}** | Top VCM | {dcm['top_vcm'] or '?'} | 🟢 Medium |
"""

            st.markdown(dcm_table)
            
            st.info("""
**💡 For Donor Compatibility:**
- **🔴 CRITICAL**: Position 4 (HSA/Slider Type) must **exactly match**
- **🟠 HIGH**: Positions 6-7, 8-9 should match for best results
- **🟡 LOW**: Positions 2-3, 5 can vary if HSA matches
- **🟢 MEDIUM**: Position 10 less critical
""")
            
            st.code(f"""
Full DCM Code: {slider_code}
Clean Code:    {clean_code}

Drive Family:    |{family_char}| = {family_name}
HSA Type:        {hsa_char} (Position 4 when excluding pipes) ← MUST MATCH
Head Family:     {head_family if head_family else 'Unknown'}

Component Breakdown:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Spindle Motor:   {dcm['spindle_motor']}
Base:            {dcm['base']}
Latch:           {dcm['latch']}
Preamp:          {dcm['preamp']}
Media Type:      {dcm['media']}
HSA (Slider):    {dcm['hsa']} ← {hsa_type}
Bottom VCM:      {dcm['bottom_vcm']}
ACA:             {dcm['aca']}
Top VCM:         {dcm['top_vcm']}

Code Location: Offset 0x26 in Module 0A
Full ROM Address: 0x0007C020

Known HSA/Slider Families:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🏖️  Pebble Beach (M16M.1 / M16M.2)
  2, 5 → Examples: |W|2J52H3F, |W|MJ62EMJ

🔭 Spyglass (M41.3A1 & 314)
  3 → Examples: |W|2J3CHMC, |W|MJ6DHMC

🌴 Palmer (M43.3B2)
  6, 7 → Examples: |W|2J6DH2C, |W|2J6CH27

Other HSA Types:
  P → EC0C_R60
  E, C, H, R, N, X, Y, K, D, M → Various HSA types
            """)
        
        # Hex dump
        slider_bytes = st.session_state.file_data[0x26:0x26+10]
        hex_str = ' '.join([f'{b:02X}' for b in slider_bytes])
        ascii_str = ''.join([chr(b) if 32 <= b < 127 else '.' for b in slider_bytes])
        st.code(f"Offset 0x26 (hex):\n{hex_str}\n\nASCII:\n{ascii_str}")
        
        # Compatibility checker
        with st.expander("🔍 Donor Compatibility Checker"):
            st.markdown("Enter a donor drive's DCM code to check compatibility:")
            donor_code = st.text_input("Donor DCM Code", placeholder="|W|2ZECH2F")
            
            if donor_code:
                _, _, donor_hsa, _ = parse_slider_info(donor_code)
                donor_family = get_head_family(donor_hsa)
                donor_dcm = parse_dcm_details(donor_code)
                
                if donor_hsa and hsa_char:
                    hsa_match = donor_hsa == hsa_char
                    family_match = head_family and donor_family and head_family == donor_family
                    
                    st.markdown("### Component-by-Component Comparison")
                    
                    comp_table = "| Component | Original | Donor | Match | Priority |\n"
                    comp_table += "|:----------|:--------:|:-----:|:-----:|:--------:|\n"
                    
                    components = [
                        ('Spindle Motor', 'spindle_motor', '🟡 Low'),
                        ('Base', 'base', '🟡 Low'),
                        ('Latch', 'latch', '🟡 Low'),
                        ('Preamp', 'preamp', '🟠 High'),
                        ('Media Type', 'media', '🟠 High'),
                        ('**HSA (Slider)**', 'hsa', '🔴 **CRITICAL**'),
                        ('Bottom VCM', 'bottom_vcm', '🟠 High'),
                        ('ACA', 'aca', '🟠 High'),
                        ('Top VCM', 'top_vcm', '🟢 Medium'),
                    ]
                    
                    for comp_name, key, priority in components:
                        orig_val = dcm.get(key, '?')
                        donor_val = donor_dcm.get(key, '?')
                        match = '✅' if orig_val == donor_val else '❌'
                        comp_table += f"| {comp_name} | **{orig_val}** | **{donor_val}** | {match} | {priority} |\n"
                    
                    st.markdown(comp_table)
                    
                    if hsa_match:
                        st.success(f"✅ **HSA MATCH** - Type {hsa_char}")
                        if family_match:
                            st.success(f"✅ **Same Head Family**: {head_family}")
                        
                        matches = sum([
                            dcm.get('preamp') == donor_dcm.get('preamp'),
                            dcm.get('media') == donor_dcm.get('media'),
                            dcm.get('bottom_vcm') == donor_dcm.get('bottom_vcm'),
                            dcm.get('aca') == donor_dcm.get('aca'),
                        ])
                        
                        if matches >= 3:
                            st.success(f"🌟 **EXCELLENT MATCH** - {matches}/4 high-priority components match")
                        elif matches >= 2:
                            st.info(f"👍 **GOOD MATCH** - {matches}/4 high-priority components match")
                        else:
                            st.warning(f"⚠️ **ACCEPTABLE** - Only {matches}/4 high-priority components match. May work but not ideal.")
                    else:
                        st.error(f"❌ **INCOMPATIBLE** - HSA types don't match!")
                        st.error(f"Original: Type {hsa_char} ({head_family or 'Unknown'}) | Donor: Type {donor_hsa} ({donor_family or 'Unknown'})")
                        st.warning("⚠️ Using mismatched HSA types will likely cause R/W failures!")
                else:
                    st.warning("Could not parse HSA type from one or both codes")
    else:
        st.warning("⚠️ Could not read DCM/slider code from Module 0A")

# --------------------------------------------------------------------
# 3. DRIVE TYPE SELECTION
# --------------------------------------------------------------------
if st.session_state.file_data is not None:
    st.markdown("---")
    st.markdown("### 3️⃣ Select Drive Type")
    
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
        if config['offset'] == 0x23:
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
                
                if is_active:
                    st.markdown(f'<span class="head-active">{status}</span>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<span class="head-inactive">{status}</span>', unsafe_allow_html=True)
        
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
            
            new_map = original_head_map
            for h in selected_heads:
                new_map ^= (1 << h)
            
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
                
                st.markdown("**📝 Changes Summary**")
                for h in selected_heads:
                    if h in active_heads:
                        st.markdown(f"- Head {h}: **Active** → **DISABLED** ❌")
                    else:
                        st.markdown(f"- Head {h}: **Inactive** → **ENABLED** ✅")
                
                # Checksum option
                update_checksum_option = False
                if config['offset'] == 0x23:
                    st.markdown("---")
                    st.markdown("#### Checksum Options")
                    update_checksum_option = st.checkbox(
                        "Update checksum after modification (Traditional drives only)",
                        value=False,
                        help="Checksum at 0x3C covers 0x1E-0x3D. Enable if you experience issues."
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
                        old_checksum = st.session_state.file_data[0x3C]
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
                    preview_data = bytearray(st.session_state.file_data)
                    offset, size = config['offset'], config['size']
                    
                    if size == 1:
                        preview_data[offset] = new_map & 0xFF
                    else:
                        preview_data[offset:offset+2] = struct.pack('<H', new_map)
                    
                    if update_checksum_option:
                        preview_data = update_checksum(preview_data)
                    
                    highlight_ranges = [(offset, offset + size)]
                    if update_checksum_option:
                        highlight_ranges.append((0x3C, 0x3D))
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Original Data**")
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
                # 8. DOWNLOAD
                # --------------------------------------------------------------------
                st.markdown("---")
                st.markdown("### 7️⃣ Download Files")
                
                mod_data = bytearray(st.session_state.file_data)
                offset, size = config['offset'], config['size']
                if size == 1:
                    mod_data[offset] = new_map & 0xFF
                else:
                    mod_data[offset:offset+2] = struct.pack('<H', new_map)
                
                if update_checksum_option:
                    mod_data = update_checksum(mod_data)
                
                original_stem = Path(st.session_state.file_name).stem
                disabled_heads = [h for h in selected_heads if h in active_heads]
                enabled_heads = [h for h in selected_heads if h not in active_heads]
                
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
                    # Get DCM info for report
                    slider_code = read_head_slider_code(st.session_state.file_data)
                    if slider_code:
                        _, _, hsa_char, hsa_type = parse_slider_info(slider_code)
                        head_family = get_head_family(hsa_char)
                    else:
                        slider_code, hsa_char, hsa_type, head_family = 'N/A', 'N/A', 'N/A', 'N/A'
                    
                    report = f"""WD Head Map Modification Report
{'=' * 50}

Original File: {st.session_state.file_name}
Output File: {output_filename}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Drive Type: {drive_type}

DCM Code: {slider_code}
HSA (Slider) Type: {hsa_char}
Preamp: {hsa_type}
Head Family: {head_family}

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
    <p>Made with ❤️ for efficiency | v2.1</p>
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
    2. **Check DCM/HSA type** for donor compatibility
    3. **Select** your drive type (auto-detected)
    4. **Review** current head map
    5. **Toggle** heads you want to enable/disable
    6. **Preview** changes in hex viewer
    7. **Download** modified file & report
    
    ### DCM Structure
    
    The DCM code encodes drive components:
    
    **Format**: `|X|ABCDEFGH`
    - **X** = Drive family (N, Q, W)
    - **Position 4** (excluding pipes) = **HSA (Slider Type)** ← Must match!
    
    **DCM Positions** (excluding pipes):
    1. Drive Family
    2. Spindle Motor
    3. Base
    4. Latch
    5. Preamp
    6. Media
    7. **HSA (Slider)** ← Critical!
    8. Bottom VCM
    9. ACA
    10. Top VCM
    
    **Examples**:
    - `|W|2ZEDEM7` → HSA Type **E** (position 4)
    - `|W|2J6DH2C` → HSA Type **6** (Palmer family)
    - `|N|HJMPDHF` → HSA Type **P**
    
    ### Head Families
    
    - 🏖️ **Pebble Beach** (2, 5) → M16M.1/M16M.2
    - 🔭 **Spyglass** (3) → M41.3A1 & 314
    - 🌴 **Palmer** (6, 7) → M43.3B2
    
    ### Drive Families
    
    - **|N|** = Firebird / FB_USB
    - **|Q|** = FB_Lite
    - **|W|** = Standard WD drives
    
    ### DCM Location
    
    - **Offset**: 0x26 in Module 0A
    - **ROM Address**: 0x0007C020
    
    ### Checksum (Traditional Drives)
    
    Traditional drives (offset 0x23):
    - Checksum at 0x3C
    - Covers bytes 0x1E through 0x3D
    - **Usually not needed** (leave unchecked)
    - Enable if drive rejects the module
    
    ### Custom Offset
    
    For unknown drive types:
    - Select "Custom Offset"
    - Enter head map location (hex)
    - Specify field size (1 or 2 bytes)
    - Set maximum heads
    
    ### Tips
    
    - HSA types must **exactly match** for R/W
    - At least one head must remain active
    - Original file is never modified
    - Use hex viewer to verify changes
    - Check DCM code before sourcing donors
    - Remember Me keeps you logged in for 30 days
    - Use Logout button to clear saved login
    """)
