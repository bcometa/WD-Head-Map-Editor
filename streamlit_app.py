"""
WD Head Map Editor - Streamlit Version
Edit Module 0A head maps for Western Digital hard drives
"""

import streamlit as st
import struct
from pathlib import Path
from datetime import datetime
import io

"""
WD Head Map Editor - Streamlit Version
Edit Module 0A head maps for Western Digital hard drives
"""

import streamlit as st
import struct
from pathlib import Path
from datetime import datetime
import io

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
}

# ... rest of helper functions ...

# --------------------------------------------------------------------
# STREAMLIT APP
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
    .info-box {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .head-active {
        color: green;
        font-weight: bold;
    }
    .head-inactive {
        color: red;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Check password before showing main app
if not check_password():
    st.stop()  # Stop execution if password is incorrect

# Main app starts here (only if password is correct)
# Header
st.markdown('<div class="main-header">💾 WD Head Map Editor</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Edit Module 0A head maps for Western Digital hard drives</div>', unsafe_allow_html=True)




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
}

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
# STREAMLIT APP
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
    .info-box {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .head-active {
        color: green;
        font-weight: bold;
    }
    .head-inactive {
        color: red;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

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
# 2. DRIVE TYPE SELECTION
# --------------------------------------------------------------------
if st.session_state.file_data is not None:
    st.markdown("---")
    st.markdown("### 2️⃣ Select Drive Type")
    
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
    
    config = DRIVE_CONFIGS[drive_type]
    
    # --------------------------------------------------------------------
    # 3. CURRENT HEAD MAP
    # --------------------------------------------------------------------
    st.markdown("---")
    st.markdown("### 3️⃣ Current Head Map")
    
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
        
        with st.expander("📊 View Detailed Head Map Info"):
            st.code(f"""
Head Map Value: 0x{original_head_map:04X}
Binary: {bin(original_head_map)}
Active Heads: {active_heads}
Head Map Offset: 0x{config['offset']:04X}
Field Size: {config['size']} byte(s)
            """)
        
        # --------------------------------------------------------------------
        # 4. HEAD SELECTION
        # --------------------------------------------------------------------
        st.markdown("---")
        st.markdown("### 4️⃣ Toggle Heads (Enable/Disable)")
        st.info("💡 Check heads to **toggle** their state. Active heads will be disabled, inactive heads will be enabled.")
        
        # Create checkboxes in columns
        cols_layout = st.columns(5)
        selected_heads = []
        
        for i in range(total_heads):
            with cols_layout[i % 5]:
                is_active = i in active_heads
                status = "✅ Active" if is_active else "❌ Inactive"
                
                # Use a unique key for each checkbox based on head index
                checkbox_key = f"head_{i}" 
                
                if st.checkbox(
                    f"Head {i}",
                    key=checkbox_key,
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
            # Reset all checkboxes and rerun
            for i in range(total_heads):
                st.session_state[f"head_{i}"] = False
            st.rerun()
        
        # --------------------------------------------------------------------
        # 5. PREVIEW
        # --------------------------------------------------------------------
        if selected_heads:
            st.markdown("---")
            st.markdown("### 5️⃣ Preview Changes")
            
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
                
                # --------------------------------------------------------------------
                # 6. SAVE
                # --------------------------------------------------------------------
                st.markdown("---")
                st.markdown("### 6️⃣ Download Files")
                
                # Create modified file data
                mod_data = bytearray(st.session_state.file_data)
                offset, size = config['offset'], config['size']
                if size == 1:
                    mod_data[offset] = new_map & 0xFF
                else:
                    mod_data[offset:offset+2] = struct.pack('<H', new_map)
                
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
    <p>Made with ❤️ for efficiency | v1.5</p>
</div>
""", unsafe_allow_html=True)

# Help sidebar
with st.sidebar:
    st.markdown("## 📖 Help Guide")
    st.markdown("""
    ### How to Use
    
    1. **Upload** your Module 0A file
    2. **Select** your drive type (auto-detected)
    3. **Check** heads you want to toggle
    4. **Preview** changes
    5. **Download** modified file & report
    
    ### Tips
    
    - At least one head must remain active
    - Active heads (green) will be DISABLED if checked
    - Inactive heads (red) will be ENABLED if checked
    - Original file is not modified
    - Download creates a new `_modified.0a` file
    """)
    # Removed Resources section as requested
