"""
Phone number intelligence module.

Inspired by SpiderFoot's phone number analysis:
- Format detection (international, national)
- Country code identification
- Number type detection (mobile, landline, VoIP)
- Validation and normalization

Features:
- International format detection
- Country code extraction
- Number length validation
- Format normalization
"""

import re
from osint_recon.colors import Colors, Status


# Country codes mapping (common ones)
COUNTRY_CODES = {
    "1": "United States/Canada",
    "7": "Russia",
    "20": "Egypt",
    "27": "South Africa",
    "30": "Greece",
    "31": "Netherlands",
    "32": "Belgium",
    "33": "France",
    "34": "Spain",
    "36": "Hungary",
    "39": "Italy",
    "44": "United Kingdom",
    "46": "Sweden",
    "49": "Germany",
    "52": "Mexico",
    "55": "Brazil",
    "61": "Australia",
    "62": "Indonesia",
    "63": "Philippines",
    "65": "Singapore",
    "81": "Japan",
    "82": "South Korea",
    "86": "China",
    "90": "Turkey",
    "91": "India",
    "92": "Pakistan",
    "93": "Afghanistan",
    "94": "Sri Lanka",
    "95": "Myanmar",
    "212": "Morocco",
    "213": "Algeria",
    "216": "Tunisia",
    "218": "Libya",
    "220": "Gambia",
    "221": "Senegal",
    "222": "Mauritania",
    "223": "Mali",
    "224": "Guinea",
    "225": "Ivory Coast",
    "226": "Burkina Faso",
    "227": "Niger",
    "228": "Togo",
    "229": "Benin",
    "230": "Mauritius",
    "231": "Liberia",
    "232": "Sierra Leone",
    "233": "Ghana",
    "234": "Nigeria",
    "235": "Chad",
    "236": "Central African Republic",
    "237": "Cameroon",
    "238": "Cape Verde",
    "239": "Sao Tome and Principe",
    "240": "Equatorial Guinea",
    "241": "Gabon",
    "242": "Congo",
    "243": "Dem. Rep. Congo",
    "244": "Angola",
    "245": "Guinea-Bissau",
    "246": "Diego Garcia",
    "247": "Ascension Island",
    "248": "Seychelles",
    "249": "Sudan",
    "250": "Rwanda",
    "251": "Ethiopia",
    "252": "Somalia",
    "253": "Djibouti",
    "254": "Kenya",
    "255": "Tanzania",
    "256": "Uganda",
    "257": "Burundi",
    "258": "Mozambique",
    "260": "Zambia",
    "261": "Madagascar",
    "262": "Reunion",
    "263": "Zimbabwe",
    "264": "Namibia",
    "265": "Malawi",
    "266": "Lesotho",
    "267": "Botswana",
    "268": "Eswatini",
    "269": "Comoros",
    "290": "Saint Helena",
    "291": "Eritrea",
    "297": "Aruba",
    "298": "Faroe Islands",
    "299": "Greenland",
    "350": "Gibraltar",
    "351": "Portugal",
    "352": "Luxembourg",
    "353": "Ireland",
    "354": "Iceland",
    "355": "Albania",
    "356": "Malta",
    "357": "Cyprus",
    "358": "Finland",
    "359": "Bulgaria",
    "370": "Lithuania",
    "371": "Latvia",
    "372": "Estonia",
    "373": "Moldova",
    "374": "Armenia",
    "375": "Belarus",
    "376": "Andorra",
    "377": "Monaco",
    "378": "San Marino",
    "380": "Ukraine",
    "381": "Serbia",
    "382": "Montenegro",
    "385": "Croatia",
    "386": "Slovenia",
    "387": "Bosnia and Herzegovina",
    "389": "North Macedonia",
    "420": "Czech Republic",
    "421": "Slovakia",
    "960": "Maldives",
    "961": "Lebanon",
    "962": "Jordan",
    "963": "Syria",
    "964": "Iraq",
    "965": "Kuwait",
    "966": "Saudi Arabia",
    "967": "Yemen",
    "968": "Oman",
    "971": "United Arab Emirates",
    "972": "Israel",
    "973": "Bahrain",
    "974": "Qatar",
    "975": "Bhutan",
    "976": "Mongolia",
    "977": "Nepal",
    "992": "Tajikistan",
    "993": "Turkmenistan",
    "994": "Azerbaijan",
    "995": "Georgia",
    "996": "Kyrgyzstan",
    "998": "Uzbekistan",
}


def normalize_phone(phone):
    """
    Normalize phone number by removing formatting characters.
    
    Removes spaces, dashes, parentheses, and dots.
    Preserves the leading + for international numbers.
    
    Args:
        phone: Phone number string
        
    Returns:
        Normalized phone number
    """
    # Keep the + if present, remove everything else non-digit
    cleaned = re.sub(r'[^\d+]', '', phone)
    return cleaned


def detect_format(phone):
    """
    Detect the format of a phone number.
    
    Returns format type and additional info.
    
    Args:
        phone: Phone number string
        
    Returns:
        Dict with format information
    """
    cleaned = normalize_phone(phone)
    digits = re.sub(r'[^\d]', '', phone)
    
    result = {
        "original": phone,
        "cleaned": cleaned,
        "digits": digits,
        "length": len(digits),
        "is_international": cleaned.startswith('+'),
        "format": "unknown",
        "country": "Unknown",
    }
    
    # Detect format based on length and prefix
    if result["is_international"]:
        result["format"] = "international"
        
        # Try to identify country code
        # Check 3-digit codes first, then 2-digit, then 1-digit
        # Country code starts at index 0 (after the + is removed from digits)
        for code_len in [3, 2, 1]:
            if len(digits) >= code_len:
                code = digits[:code_len]
                if code in COUNTRY_CODES:
                    result["country"] = COUNTRY_CODES[code]
                    result["country_code"] = f"+{code}"
                    break
    else:
        result["format"] = "national"
        
        # Detect by length
        if len(digits) == 10:
            result["format"] = "US/Canada (10-digit)"
        elif len(digits) == 11 and digits.startswith('1'):
            result["format"] = "US/Canada with country code"
        elif len(digits) == 11:
            result["format"] = "International (11-digit)"
    
    return result


def validate_phone(phone):
    """
    Validate phone number format.
    
    Checks:
    - Minimum length (7 digits)
    - Maximum length (15 digits per E.164)
    - Contains only valid characters
    
    Args:
        phone: Phone number string
        
    Returns:
        Tuple of (is_valid, reason)
    """
    cleaned = normalize_phone(phone)
    digits = re.sub(r'[^\d]', '', phone)
    
    if len(digits) < 7:
        return False, "Too short (minimum 7 digits)"
    
    if len(digits) > 15:
        return False, "Too long (maximum 15 digits per E.164)"
    
    if not re.match(r'^\+?[\d\s\-\(\)]{7,20}$', phone):
        return False, "Contains invalid characters"
    
    return True, "Valid"


def format_as_e164(phone):
    """
    Format phone number to E.164 format.
    
    E.164 format: +[country code][subscriber number]
    Example: +14155552671
    
    Args:
        phone: Phone number string
        
    Returns:
        E.164 formatted string
    """
    cleaned = normalize_phone(phone)
    
    if not cleaned.startswith('+'):
        # Assume US/Canada if no country code
        if len(cleaned) == 10:
            return f"+1{cleaned}"
        elif len(cleaned) == 11 and cleaned.startswith('1'):
            return f"+{cleaned}"
    
    return cleaned


def analyze_phone(phone, verbose=False):
    """
    Main function for phone number intelligence.
    
    Analyzes a phone number and provides:
    - Format detection
    - Country identification
    - Validation
    - E.164 normalization
    
    Args:
        phone: Target phone number
        verbose: Enable verbose output
        
    Returns:
        Dict with phone intelligence
    """
    # Display header
    print(f"\n{Status.INFO} {Colors.BOLD}Phone Number Intelligence: {phone}{Colors.ENDC}\n")
    results = {}
    
    # Normalize the number
    cleaned = normalize_phone(phone)
    results['cleaned'] = cleaned
    
    # Validate
    is_valid, reason = validate_phone(phone)
    results['valid'] = is_valid
    results['validation_reason'] = reason
    
    if not is_valid:
        print(f"  {Status.ERROR} {Colors.FAIL}Invalid phone number: {reason}{Colors.ENDC}")
        return results
    
    # Detect format
    format_info = detect_format(phone)
    results['format'] = format_info
    
    print(f"  {Colors.CYAN}Format        :{Colors.ENDC} {format_info['format']}")
    print(f"  {Colors.CYAN}Length        :{Colors.ENDC} {format_info['length']} digits")
    print(f"  {Colors.CYAN}International :{Colors.ENDC} {'Yes' if format_info['is_international'] else 'No'}")
    
    if format_info.get('country') and format_info['country'] != 'Unknown':
        print(f"  {Colors.CYAN}Country       :{Colors.ENDC} {format_info['country']}")
        print(f"  {Colors.CYAN}Country Code  :{Colors.ENDC} {format_info.get('country_code', 'N/A')}")
    
    # E.164 format
    e164 = format_as_e164(phone)
    results['e164'] = e164
    print(f"\n  {Colors.CYAN}E.164 Format  :{Colors.ENDC} {e164}")
    
    # Additional analysis
    print(f"\n  {Colors.CYAN}Raw Digits    :{Colors.ENDC} {format_info['digits']}")
    
    if verbose:
        print(f"\n  {Colors.DIM}--- Additional Info ---{Colors.ENDC}")
        print(f"  {Colors.DIM}Original      : {phone}{Colors.ENDC}")
        print(f"  {Colors.DIM}Cleaned       : {cleaned}{Colors.ENDC}")
    
    return results
