import pandas as pd
import os


# ==========================================
# NSL-KDD Column Names
# ==========================================

NSL_KDD_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "attack",
    "difficulty"
]


# ==========================================
# Common Network Feature Aliases
# ==========================================

FEATURE_ALIASES = {

    "duration": [
        "duration",
        "flow_duration",
        "dur"
    ],

    "protocol_type": [
        "protocol_type",
        "protocol",
        "proto"
    ],

    "service": [
        "service",
        "application",
        "service_name"
    ],

    "flag": [
        "flag",
        "tcp_flags",
        "flags"
    ],

    "src_bytes": [
        "src_bytes",
        "source_bytes",
        "total_source_bytes",
        "bytes_sent"
    ],

    "dst_bytes": [
        "dst_bytes",
        "destination_bytes",
        "total_destination_bytes",
        "bytes_received"
    ],

    "src_ip": [
        "src_ip",
        "source_ip",
        "srcip",
        "source_address"
    ],

    "dst_ip": [
        "dst_ip",
        "destination_ip",
        "dstip",
        "destination_address"
    ],

    "src_port": [
        "src_port",
        "source_port",
        "sport"
    ],

    "dst_port": [
        "dst_port",
        "destination_port",
        "dport"
    ],

    "packet_count": [
        "packet_count",
        "total_packets",
        "packets"
    ],

    "packet_length": [
        "packet_length",
        "packet_len",
        "length",
        "packet_size"
    ],

    "bytes": [
        "bytes",
        "total_bytes",
        "total_length"
    ],

    "flow_packets": [
        "flow_packets",
        "flow_packet_count"
    ],

    "flow_bytes": [
        "flow_bytes",
        "flow_byte_count"
    ]
}


# ==========================================
# Normalize Column Name
# ==========================================

def normalize_column_name(name):

    name = str(name).strip().lower()

    name = name.replace("-", "_")
    name = name.replace(" ", "_")

    return name


# ==========================================
# Detect Network Features
# ==========================================

def detect_network_features(data):

    normalized_columns = {}

    for column in data.columns:

        normalized = normalize_column_name(
            column
        )

        normalized_columns[
            normalized
        ] = column

    matched_features = {}

    for standard_feature, aliases in FEATURE_ALIASES.items():

        for alias in aliases:

            alias_normalized = normalize_column_name(
                alias
            )

            if alias_normalized in normalized_columns:

                matched_features[
                    standard_feature
                ] = normalized_columns[
                    alias_normalized
                ]

                break

    return matched_features


# ==========================================
# Check NSL-KDD Format
# ==========================================

def is_nsl_kdd_format(data):

    if len(data.columns) != 43:
        return False

    normalized_columns = [
        normalize_column_name(column)
        for column in data.columns
    ]

    expected_columns = [
        normalize_column_name(column)
        for column in NSL_KDD_COLUMNS
    ]

    return normalized_columns == expected_columns


# ==========================================
# Read Network File
# ==========================================

def read_network_file(file_path):

    # --------------------------------------
    # First try normal header-based CSV
    # --------------------------------------

    try:

        data_header = pd.read_csv(
            file_path
        )

        header_columns = [
            normalize_column_name(column)
            for column in data_header.columns
        ]

        # ----------------------------------
        # Check if normal network header
        # ----------------------------------

        matched = detect_network_features(
            data_header
        )

        if len(matched) >= 2:

            return data_header, "header"


        # ----------------------------------
        # Check possible KDD structure
        # ----------------------------------

        if len(data_header.columns) == 43:

            data_kdd = pd.read_csv(
                file_path,
                names=NSL_KDD_COLUMNS,
                header=None
            )

            return data_kdd, "nsl_kdd"

    except Exception:
        pass


    # --------------------------------------
    # Try headerless NSL-KDD format
    # --------------------------------------

    try:

        data_kdd = pd.read_csv(
            file_path,
            names=NSL_KDD_COLUMNS,
            header=None
        )

        if len(data_kdd.columns) == 43:

            return data_kdd, "nsl_kdd"

    except Exception:

        pass


    return None, None


# ==========================================
# Analyze Network File
# ==========================================

def analyze_network_file(file_path):

    result = {

        "filename": os.path.basename(
            file_path
        ),

        "rows": 0,

        "columns": 0,

        "column_names": [],

        "matched_features": {},

        "matched_count": 0,

        "format": "",

        "network_file": False,

        "message": ""
    }


    # ======================================
    # Check Extension
    # ======================================

    extension = os.path.splitext(
        file_path
    )[1].lower()

    if extension not in [".csv", ".txt"]:

        result["message"] = (
            "Only CSV and TXT files are supported."
        )

        return result


    # ======================================
    # Read File
    # ======================================

    data, file_format = read_network_file(
        file_path
    )

    if data is None:

        result["message"] = (
            "Unable to identify the network "
            "dataset format."
        )

        return result


    # ======================================
    # Basic Information
    # ======================================

    result["rows"] = len(data)

    result["columns"] = len(data.columns)

    result["column_names"] = (
        data.columns.tolist()
    )

    result["format"] = file_format


    # ======================================
    # Feature Detection
    # ======================================

    matched = detect_network_features(
        data
    )

    result["matched_features"] = matched

    result["matched_count"] = len(
        matched
    )


    # ======================================
    # Network Indicators
    # ======================================

    network_indicators = [

        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol_type",
        "duration",
        "src_bytes",
        "dst_bytes",
        "packet_count",
        "packet_length"
    ]


    network_match_count = sum(

        1

        for feature in network_indicators

        if feature in matched
    )


    # ======================================
    # NSL-KDD Special Case
    # ======================================

    if file_format == "nsl_kdd":

        result["network_file"] = True

        result["message"] = (
            "NSL-KDD network traffic dataset detected."
        )

    elif network_match_count >= 2:

        result["network_file"] = True

        result["message"] = (
            "Network traffic dataset detected."
        )

    else:

        result["network_file"] = False

        result["message"] = (
            "File does not contain sufficient "
            "network traffic features."
        )


    return result


# ==========================================
# Test
# ==========================================

if __name__ == "__main__":

    file_path = input(
        "Enter CSV/TXT file path: "
    ).strip()


    result = analyze_network_file(
        file_path
    )


    print("\n==============================")
    print("UNIVERSAL NETWORK FILE ANALYZER")
    print("==============================")


    print(
        "File:",
        result["filename"]
    )


    print(
        "Rows:",
        result["rows"]
    )


    print(
        "Columns:",
        result["columns"]
    )


    print(
        "Detected Format:",
        result["format"]
    )


    print(
        "\nMatched Features:"
    )


    for standard, original in result[
        "matched_features"
    ].items():

        print(
            f"{standard} -> {original}"
        )


    print(
        "\nMatched Feature Count:",
        result["matched_count"]
    )


    print(
        "\nNetwork File:",
        result["network_file"]
    )


    print(
        "Message:",
        result["message"]
    )