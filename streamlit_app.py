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

# Known HSA/slider/preamp type mappings (4th character = HSA type)
# Enhanced with head family information
SLIDER_PREAMP_TYPES = {
    # Palmer Family
    '7': 'M43.3B2 (Palmer)',
    '6': 'M43.3B2 (Palmer)',
    
    # Spyglass Family  
    '3': 'M41.3A1 & 314 (Spyglass)',
    
    # Pebble Beach Family
    '2': 'M16M.1 (Pebble Beach)',
    '5': 'M16M.1/M16M.2 (Pebble Beach)',
    
    # Other specific types
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

# --------------------------------------------------------------------
# HEAD FAMILY DETECTION
# --------------------------------------------------------------------
def get_head_family(hsa_char):
    """Identify head family (Pebble Beach, Spyglass, Palmer) from HSA character"""
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
